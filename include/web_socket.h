#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"

// WebSocket frame opcodes
#define WS_OPCODE_CONTINUATION 0x0
#define WS_OPCODE_TEXT         0x1
#define WS_OPCODE_BINARY       0x2
#define WS_OPCODE_CLOSE        0x8
#define WS_OPCODE_PING         0x9
#define WS_OPCODE_PONG         0xA

#include "freertos/queue.h"

/**
 * Start Websocket server
 *
 * @param receiver Function to call when a message is received from a client
 */
void ws_server_start(void (*receiver)(const char *message));

/**
 * Stop the Websocket server
 */
void ws_server_stop(void);

/**
 * Get the current length of the WebSocket send queue
 */
int ws_send_queue_length();

/**
 * Send a message to all connected WebSocket clients
 * 
 * @param data Null-terminated string to send
 */
void ws_send(const char *data);
