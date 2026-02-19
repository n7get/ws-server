# ws-server

An ESP-IDF component that implements a WebSocket server for ESP32 microcontrollers. It provides a lightweight, concurrent WebSocket server supporting multiple simultaneous client connections and bidirectional communication.

## Features

- WebSocket protocol (RFC 6455) compliant
- Up to 4 concurrent client connections
- Automatic keepalive via ping/pong frames (30-second intervals)
- Queue-based broadcasting to all connected clients
- Thread-safe client management using FreeRTOS semaphores
- SHA1/Base64 WebSocket handshake via mbedTLS

## Supported Targets

esp32, esp32s2, esp32s3, esp32c3, esp32c2, esp32c6, esp32h2

## Requirements

- ESP-IDF >= 5.0.0
- [esp-utils](https://github.com/your-repo/esp-utils) >= 0.1.1

## Installation

Place this component in your project's `components/` directory:

```
your-project/
├── components/
│   └── ws-server/
├── main/
└── CMakeLists.txt
```

## Usage

```c
#include "web_socket.h"

void on_message(const char *message) {
    printf("Received: %s\n", message);
    ws_send("Hello from ESP32!");
}

void app_main(void) {
    // ... Wi-Fi initialization ...

    ws_server_start(on_message);
}
```

Connect to the server at `ws://<device-ip>:8080`.

## API

### `ws_server_start`

```c
void ws_server_start(void (*receiver)(const char *message));
```

Starts the WebSocket server. The `receiver` callback is called with the text payload whenever a message is received from any client.

### `ws_server_stop`

```c
void ws_server_stop(void);
```

Gracefully stops the server, closes all client connections, and frees resources.

### `ws_send`

```c
void ws_send(const char *data);
```

Broadcasts a null-terminated text message to all connected clients via an internal message queue.

### `ws_send_queue_length`

```c
int ws_send_queue_length(void);
```

Returns the number of messages currently pending in the send queue.

## Configuration

These options are configurable via ESP-IDF menuconfig:

```bash
idf.py menuconfig
```

Navigate to:

- `Component config` → `WebSocket Server`

Available options:

| Constant | Default | Description |
|---|---|---|
| `WS_SERVER_PORT` | `8080` | Listening port |
| `WS_MAX_CLIENTS` | `4` | Maximum concurrent connections |
| `WS_RECV_BUFFER_SIZE` | `2048` | Per-client receive buffer size (bytes) |

Internal constants in `src/web_socket.c`:

| Constant | Default | Description |
|---|---|---|
| `WS_QUEUE_SIZE` | `300` | Message queue capacity |
| `PING_TIMER` | `30000` | Keepalive ping interval (ms) |

## Architecture

The server runs three FreeRTOS tasks:

- **Server task** — Accepts incoming TCP connections and spawns a handler per client.
- **Client handler task** — Performs the WebSocket handshake, then reads and processes frames from a single client.
- **Broadcast task** — Dequeues outgoing messages and sends them to all connected clients.

A FreeRTOS timer sends PING frames every 30 seconds. Clients that miss 3 consecutive pings are disconnected.

## License

MIT — see [LICENSE](LICENSE) for details.
