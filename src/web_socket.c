#include "web_socket.h"

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "mbedtls/base64.h"
#include "mbedtls/sha1.h"
#include "esp_log.h"
#include "mem_helpers.h"

#include "linked_list.h"

#define TAG "WS_SERVER"
#define WS_QUEUE_SIZE 300
#define PING_TIMER 30000

static int server_fd = -1;
static TaskHandle_t ws_server_task_handle = NULL;
static QueueHandle_t ws_send_queue = NULL;
TimerHandle_t keepalive_timer = NULL;

typedef struct {
    int fd;
    TaskHandle_t task;
    int ping_count;
    volatile bool shutdown_requested;
    void (*receiver)(const char *message);
} ws_client_t;

static linked_list_t *ws_clients = NULL;
static SemaphoreHandle_t ws_clients_mutex = NULL;

static void ws_handle_client(void *param);
static int ws_handshake(int client_fd);
static int ws_recv_frame(int client_fd, char *buffer, size_t len);
static void ws_broadcast_task(void *param);

static void tagged_free(void *ptr) {
    log_free(TAG, ptr);
}

#define LOG_BUFFERS 0
#if LOG_BUFFERS
#define DUMP_WIDTH 12
static char *dump_hex(uint8_t *data, size_t len) {
    char *buf = log_malloc(TAG, "dump_hex_buf", DUMP_WIDTH * 3 + 1); // 2 hex digits + space + null terminator
    if (!buf) return NULL;

    char *ptr = buf;
    for (size_t i = 0; i < DUMP_WIDTH; i++) {
        if (i < len) {
            ptr += sprintf(ptr, "%02x ", data[i]);
        } else {
            ptr += sprintf(ptr, "   ");
        }
    }
    *ptr = '\0';
    return buf;
}
static char *dump_ascii(uint8_t *data, size_t len) {
    char *buf = log_malloc(TAG, "dump_ascii_buf", DUMP_WIDTH + 1);
    if (!buf) return NULL;

    char *ptr = buf;
    for (size_t i = 0; i < DUMP_WIDTH; i++) {
        if (i < len) {
            if (data[i] >= 32 && data[i] <= 126) {
                *ptr++ = data[i];
            } else {
                *ptr++ = '.';
            }
        } else {
            *ptr++ = ' ';
        }
    }

    *ptr = '\0';
    return buf;
}

static void log_buffer(const char *tag, const void *buffer, size_t len) {
    const uint8_t *data = (const uint8_t *)buffer;
    ESP_LOGI(tag, "Buffer content (%zu bytes):", len);
    while (len > 0) {
        size_t line_len = len < DUMP_WIDTH ? len : DUMP_WIDTH;
        char *hex = dump_hex((uint8_t *)data, line_len);
        char *ascii = dump_ascii((uint8_t *)data, line_len);
        if (hex && ascii) {
            ESP_LOGI(tag, "%s |%s|", hex, ascii);
        } else {
            ESP_LOGE(tag, "Failed to allocate memory for logging buffer");
        }
        log_free(TAG, hex);
        log_free(TAG, ascii);
        data += line_len;
        len -= line_len;
    }
}

static ssize_t ws_recv(int s, void *mem, size_t len, int flags) {
    ESP_LOGI(TAG, "Reading data: s=%d, len=%zu, flags=%d", s, len, flags);
    int recv_len = recv(s, mem, len, flags);
    if (recv_len < 0) {
        ESP_LOGE(TAG, "Receive error: errno %d", errno);
        return -1;
    }
    if (recv_len == 0) {
        ESP_LOGI(TAG, "Connection closed by peer");
        return 0;
    }
    log_buffer(TAG, mem, recv_len);
    return recv_len;
}
static size_t ws_write(int s, const void *data, size_t size, int flags) {
    ESP_LOGI(TAG, "Writing data: s=%d, size=%zu, flags=%d", s, size, flags);
    if (data == NULL || size == 0) {
        ESP_LOGE(TAG, "Invalid data or size for ws_write");
        return 0;
    }
    log_buffer(TAG, data, size);
    ssize_t sent = send(s, data, size, flags);
    if (sent < 0) {
        ESP_LOGE(TAG, "Send error: errno %d", errno);
        return 0;
    }
    return sent;
}
#else
#define ws_recv(s, mem, len, flags) recv(s, mem, len, flags)
#define ws_write(s, data, size, flags) send(s, data, size, flags)
#endif

static void ws_server_task(void *pvParameters) {
    void (*receiver)(const char *message) = pvParameters;
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_fd < 0) {
            ESP_LOGE(TAG, "Unable to accept connection: errno %d", errno);
            continue;
        }

        ws_client_t *client = log_calloc(TAG, "ws_client_t", 1, sizeof(ws_client_t));
        if (!client) {
            ESP_LOGE(TAG, "Failed to allocate ws_client_t");
            close(client_fd);
            continue;
        }
        client->fd = client_fd;
        client->shutdown_requested = false;
        client->receiver = receiver;

        xSemaphoreTake(ws_clients_mutex, portMAX_DELAY);
        linked_list_push(ws_clients, client);
        xSemaphoreGive(ws_clients_mutex);

        xTaskCreate(ws_handle_client, "ws_client_task", 4096, client, 5, &client->task);
    }
}

// Minimal WebSocket frame send (text only)
static int ws_send_frame(int client_fd, const char *data, size_t len, uint8_t opcode) {
    uint8_t hdr[10];
    int hdr_len = 0;
    hdr[0] = 0x80 | (opcode & 0x0F);
    if (len < 126) {
        hdr[1] = len;
        hdr_len = 2;
    } else if (len < 65536) {
        hdr[1] = 126;
        hdr[2] = (len >> 8) & 0xFF;
        hdr[3] = len & 0xFF;
        hdr_len = 4;
    } else {
        hdr[1] = 127;
        for (int i = 0; i < 8; ++i)
            hdr[2 + i] = (len >> (56 - 8 * i)) & 0xFF;
        hdr_len = 10;
    }

    if (ws_write(client_fd, hdr, hdr_len, 0) != hdr_len) {
        return -1;
    }

    if (data != NULL && len > 0) {
        if (ws_write(client_fd, data, len, 0) != len) {
            return -1;
        }
    }
    return 0;
}

static void keepalive(TimerHandle_t xTimer) {
    xSemaphoreTake(ws_clients_mutex, portMAX_DELAY);
    for (linked_list_node_t *node = linked_list_begin(ws_clients); node != NULL; node = linked_list_next(node)) {
        ws_client_t *client = (ws_client_t *)node->data;
        
        // Skip clients already marked for shutdown
        if (client->shutdown_requested) {
            continue;
        }
        
        client->ping_count++;
        if (client->ping_count > 3) {
            ESP_LOGI(TAG, "Client %d is inactive, requesting shutdown", client->fd);
            client->shutdown_requested = true;
            // Send close frame to trigger graceful shutdown
            ws_send_frame(client->fd, NULL, 0, WS_OPCODE_CLOSE);
            // Shutdown socket to unblock any pending recv operations
            shutdown(client->fd, SHUT_RDWR);
            continue;
        }

        if (ws_send_frame(client->fd, NULL, 0, WS_OPCODE_PING) != 0) {
            ESP_LOGE(TAG, "Failed to send PING to client %d", client->fd);
        }
    }
    xSemaphoreGive(ws_clients_mutex);
}

void ws_server_start(void (*receiver)(const char *message)) {
    ws_send_queue = xQueueCreate(WS_QUEUE_SIZE, sizeof(char *));
    if (ws_send_queue == NULL) {
        ESP_LOGE(TAG, "Failed to create WebSocket send queue");
        return;
    }
    
    if (!ws_clients_mutex) {
        ws_clients_mutex = xSemaphoreCreateMutex();
    }
    if (!ws_clients) {
        ws_clients = linked_list_create();
    } else {
        linked_list_clear(ws_clients, tagged_free);
    }

    if (keepalive_timer == NULL ) {
        keepalive_timer = xTimerCreate("keepalive", pdMS_TO_TICKS(PING_TIMER), pdTRUE, NULL, keepalive);
        if (xTimerStart(keepalive_timer, 0) != pdPASS) {
            ESP_LOGE(TAG, "Failed to start keepalive timer");
            return;
        }
    }

    server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (server_fd < 0) {
        ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
        return;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(WS_SERVER_PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) !=
        0) {
        ESP_LOGE(TAG, "Socket unable to bind: errno %d", errno);
        close(server_fd);
        server_fd = -1;
        return;
    }

    if (listen(server_fd, WS_MAX_CLIENTS) != 0) {
        ESP_LOGE(TAG, "Error occurred during listen: errno %d", errno);
        close(server_fd);
        server_fd = -1;
        return;
    }

    ESP_LOGI(TAG, "WebSocket server listening on port %d", WS_SERVER_PORT);

    xTaskCreate(ws_server_task, "ws_server_task", 4096, receiver, 5, &ws_server_task_handle);

    xTaskCreate(ws_broadcast_task, "ws_broadcast_task", 4096, NULL, 5, NULL);
}

void ws_server_stop(void) {
    if (server_fd >= 0) {
        close(server_fd);
        server_fd = -1;
    }

    if (keepalive_timer) {
        xTimerStop(keepalive_timer, 0);
        xTimerDelete(keepalive_timer, 0);
        keepalive_timer = NULL;
    }

    if (ws_server_task_handle) {
        vTaskDelete(ws_server_task_handle);
        ws_server_task_handle = NULL;
    }

    // Signal all client tasks to shutdown and close their sockets
    if (ws_clients && ws_clients_mutex) {
        xSemaphoreTake(ws_clients_mutex, portMAX_DELAY);

        for (linked_list_node_t *node = linked_list_begin(ws_clients); node != NULL; node = linked_list_next(node)) {
            ws_client_t *client = (ws_client_t *)node->data;
            client->shutdown_requested = true;
            if (client->fd != -1) {
                shutdown(client->fd, SHUT_RDWR);
                close(client->fd);
                client->fd = -1;
            }
        }

        xSemaphoreGive(ws_clients_mutex);
        
        // Give tasks time to cleanup
        vTaskDelay(pdMS_TO_TICKS(100));
        
        // Now safe to destroy client list
        xSemaphoreTake(ws_clients_mutex, portMAX_DELAY);
        linked_list_destroy(ws_clients, tagged_free);
        ws_clients = NULL;
        xSemaphoreGive(ws_clients_mutex);
    }

    // Delete mutex last, after all operations complete
    if (ws_clients_mutex) {
        vSemaphoreDelete(ws_clients_mutex);
        ws_clients_mutex = NULL;
    }

    if (ws_send_queue) {
        vQueueDelete(ws_send_queue);
        ws_send_queue = NULL;
    }
}

static void ws_handle_client(void *param) {
    ws_client_t *client = (ws_client_t *)param;
    ESP_LOGI(TAG, "New client connected: fd=%d", client->fd);

    // Set socket timeout to allow periodic checking of shutdown flag
    struct timeval timeout;
    timeout.tv_sec = 5;  // 5 second timeout
    timeout.tv_usec = 0;
    setsockopt(client->fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    if (ws_handshake(client->fd) != 0) {
        ESP_LOGE(TAG, "WebSocket handshake failed");
        goto cleanup;
    }

    ESP_LOGI(TAG, "WebSocket handshake successful for client fd=%d", client->fd);

    char *buffer = log_malloc(TAG, "ws_handle_client_buffer", WS_RECV_BUFFER_SIZE);
    if (!buffer) {
        ESP_LOGE(TAG, "Failed to allocate buffer");
        goto cleanup;
    }

    while (!client->shutdown_requested) {
        int len = ws_recv_frame(client->fd, buffer, WS_RECV_BUFFER_SIZE);
        if (len < 0) {
            break;
        }
        if (len == 0) {
            continue;
        }

        buffer[len] = '\0';
        ESP_LOGI(TAG, "Received: %s", buffer);

        client->receiver(buffer);
    }

    log_free(TAG, buffer);

    ESP_LOGI(TAG, "Client disconnected, closing connection");

cleanup:
    xSemaphoreTake(ws_clients_mutex, portMAX_DELAY);

    if (client->fd != -1) {
        close(client->fd);
    }
    linked_list_remove(ws_clients, client);
    log_free(TAG, client);

    xSemaphoreGive(ws_clients_mutex);

    vTaskDelete(NULL);
}

#define IO_BUFFER_SIZE 1024
static int ws_handshake(int client_fd) {
    char *recv_buf = log_malloc(TAG, "ws_handshake_recv_buf", IO_BUFFER_SIZE);
    char *send_buf = log_malloc(TAG, "ws_handshake_send_buf", IO_BUFFER_SIZE);
    char sec_websocket_key[128] = {0};

    int len = ws_recv(client_fd, recv_buf, IO_BUFFER_SIZE - 1, 0);
    if (len <= 0) {
        log_free(TAG, recv_buf);
        log_free(TAG, send_buf);
        return -1;
    }
    recv_buf[len] = '\0';

    char *key_hdr = strstr(recv_buf, "Sec-WebSocket-Key: ");
    if (!key_hdr) {
        log_free(TAG, recv_buf);
        log_free(TAG, send_buf);
        return -1;
    }
    key_hdr += strlen("Sec-WebSocket-Key: ");

    char *key_end = strstr(key_hdr, "\r\n");
    if (!key_end) {
        log_free(TAG, recv_buf);
        log_free(TAG, send_buf);
        return -1;
    }
    int key_len = key_end - key_hdr;
    strncpy(sec_websocket_key, key_hdr, key_len);
    sec_websocket_key[key_len] = '\0';

    // Concatenate with magic string
    char *accept_src = log_malloc(TAG, "ws_handshake_accept_src", strlen(sec_websocket_key) + 128);
    snprintf(accept_src, strlen(sec_websocket_key) + 128, "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", sec_websocket_key);

    // SHA1 hash
    unsigned char sha1_out[20];
    mbedtls_sha1((unsigned char *)accept_src, strlen(accept_src), sha1_out);
    log_free(TAG, accept_src);

    // Base64 encode
    size_t olen;
    mbedtls_base64_encode((unsigned char *)send_buf, IO_BUFFER_SIZE, &olen, sha1_out, 20);
    send_buf[olen] = '\0';

    // Build response
    char *response = log_malloc(TAG, "ws_handshake_response", IO_BUFFER_SIZE);
    snprintf(response, IO_BUFFER_SIZE,
             "HTTP/1.1 101 Switching Protocols\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             "Sec-WebSocket-Accept: %s\r\n\r\n",
             send_buf);
    ws_write(client_fd, response, strlen(response), 0);
    log_free(TAG, response);
    log_free(TAG, recv_buf);
    log_free(TAG, send_buf);

    return 0;
}

// Minimal WebSocket frame ws_recv (text only, no fragmentation, no mask from
// client)
static int ws_recv_frame(int client_fd, char *buffer, size_t len) {
    uint8_t hdr[2];

    int r = ws_recv(client_fd, hdr, 2, 0);
    if (r != 2) {
        // Check if it's a timeout (EAGAIN/EWOULDBLOCK) vs real error
        if (r == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return 0; // Timeout, not an error - return 0 to continue
        }
        return -1; // Real error or disconnect
    }

    uint8_t opcode = hdr[0] & 0x0F;
    uint8_t mask = hdr[1] & 0x80;

    uint64_t payload_len = hdr[1] & 0x7F;
    if (payload_len == 126) {
        uint8_t ext[2];
        if (ws_recv(client_fd, ext, 2, 0) != 2) {
            return -1;
        }
        payload_len = (ext[0] << 8) | ext[1];
    } else if (payload_len == 127) {
        uint8_t ext[8];
        if (ws_recv(client_fd, ext, 8, 0) != 8) {
            return -1;
        }
        payload_len = 0;
        for (int i = 0; i < 8; ++i) {
            payload_len = (payload_len << 8) | ext[i];
        }
    }

    uint8_t masking_key[4];
    if (mask) {
        if (ws_recv(client_fd, masking_key, 4, 0) != 4) {
            return -1;
        }
    }

    if (payload_len > len - 1) {
        return -1;
    }

    int recvd = 0;
    while (recvd < payload_len) {
        int r = ws_recv(client_fd, buffer + recvd, payload_len - recvd, 0);
        if (r <= 0) {
            return -1;
        }
        recvd += r;
    }
    if (mask) {
        for (uint64_t i = 0; i < payload_len; ++i) {
            buffer[i] ^= masking_key[i % 4];
        }
    }

    switch(opcode) {
    case WS_OPCODE_TEXT:
       return payload_len;

    case WS_OPCODE_CLOSE:
        if (payload_len > 0) {
            uint8_t close_code[2];
            close_code[0] = buffer[0];
            close_code[1] = buffer[1];

            ESP_LOGI(TAG, "Client requested close with code: %d", (close_code[0] << 8) | close_code[1]);

            if (payload_len > 2) {
                ESP_LOGI(TAG, "Close reason: %s", buffer + 2);
            } else {
                ESP_LOGI(TAG, "Close reason: No reason provided");
            }

            if (ws_send_frame(client_fd, buffer, 2, WS_OPCODE_CLOSE) != 0) {
                ESP_LOGE(TAG, "Failed to send CLOSE frame to client %d", client_fd);
            }
        } else {
            ESP_LOGI(TAG, "Client requested close with no code or reason");

            if (ws_send_frame(client_fd, NULL, 0, WS_OPCODE_CLOSE) != 0) {
                ESP_LOGE(TAG, "Failed to send CLOSE frame to client %d", client_fd);
            }
        }
        return -1; // Indicate client closed connection

    case WS_OPCODE_PING:
        if (ws_send_frame(client_fd, NULL, 0, WS_OPCODE_PONG) != 0) {
            ESP_LOGE(TAG, "Failed to send PONG frame to client %d", client_fd);
            return -1;
        }
        return 0;

    case WS_OPCODE_PONG:
        xSemaphoreTake(ws_clients_mutex, portMAX_DELAY);
        for (linked_list_node_t *node = linked_list_begin(ws_clients); node != NULL; node = linked_list_next(node)) {
            ws_client_t *client = (ws_client_t *)node->data;
            if (client->fd == client_fd) {
                client->ping_count = 0;
                break;
            }
        }
        xSemaphoreGive(ws_clients_mutex);
        return 0;
        
    default:
        ESP_LOGE(TAG, "Unsupported WebSocket opcode: %d", opcode);
        return 0; // Ignore unsupported opcodes
    }
}

// Broadcast a text message to all connected clients
static void ws_broadcast_text(const char *msg) {
    xSemaphoreTake(ws_clients_mutex, portMAX_DELAY);

    for (linked_list_node_t *node = linked_list_begin(ws_clients); node != NULL; node = linked_list_next(node)) {
        ws_client_t *client = (ws_client_t *)node->data;
        
        // Skip clients already marked for shutdown
        if (client->shutdown_requested || client->fd == -1) {
            continue;
        }
        
        if (ws_send_frame(client->fd, msg, strlen(msg), WS_OPCODE_TEXT) != 0) {
            ESP_LOGE(TAG, "Failed to send message to client %d, triggering shutdown", client->fd);
            // Mark for shutdown - the client task will clean up
            client->shutdown_requested = true;
            shutdown(client->fd, SHUT_RDWR);
        }
    }

    xSemaphoreGive(ws_clients_mutex);
}

// Task to send messages from the queue to all clients
static void ws_broadcast_task(void *param) {
    char *msg;

    while (1) {
        if (xQueueReceive(ws_send_queue, &msg, portMAX_DELAY) == pdTRUE) {
            ws_broadcast_text(msg);
            log_free(TAG, msg);
        }
    }
}

int ws_send_queue_length() {
    if (ws_send_queue == NULL) {
        ESP_LOGE(TAG, "WebSocket queue not initialized");
        return -1;
    }
    return uxQueueMessagesWaiting(ws_send_queue);
}

void ws_send(const char *data) {
    if (ws_send_queue == NULL) {
        ESP_LOGE(TAG, "WebSocket queue not initialized");
        return;
    }

    char *buf = log_malloc(TAG, "ws_send_buf", strlen(data) + 1);
    if (buf == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for WebSocket message");
        return;
    }
    strcpy(buf, (char *)data);

    if (xQueueSend(ws_send_queue, &buf, portMAX_DELAY) != pdTRUE) {
        ESP_LOGE(TAG, "Failed to enqueue WebSocket message");
    }
}
