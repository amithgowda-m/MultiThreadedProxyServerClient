# Advanced Multi-Threaded HTTP/HTTPS Proxy Server

A high-performance Proxy Server implemented in C that handles **HTTP**, **HTTPS (via Tunneling)**, and **caching**. It uses POSIX threads (`pthread`) for concurrency, semaphores for synchronization, and a custom LRU (Least Recently Used) Cache.

## 🚀 Key Features (Why this project is complex)

### 1. Dual-Mode Proxying
* **HTTP (Layer 7):** Parses requests, inspects headers, and caches responses to reduce bandwidth.
* **HTTPS (Layer 4 Tunneling):** Implements the HTTP `CONNECT` method to create a blind TCP tunnel. Uses `select()` for I/O multiplexing to handle bidirectional encrypted traffic without breaking SSL/TLS.

### 2. Concurrency & Synchronization
* Uses a **Thread Pool** architecture to handle multiple clients simultaneously.
* **Semaphores** control the maximum number of active clients.
* **Mutex Locks** ensure thread-safe access to the shared Cache and Log file.

### 3. Caching System
* Implements a custom **LRU (Least Recently Used)** cache using a linked list.
* Automatically evicts old entries when the cache is full (200MB limit).

### 4. Security & Auditing
* **Blacklisting:** Blocks access to specific domains defined in `blocked.txt`.
* **Logging:** Records all traffic (IP, URL, Status Code) to `server.log` for auditing.

## 🛠️ Project Structure

* `proxy_server_with_cache.c`: Main server logic (Socket creation, Threading, Tunneling).
* `proxy_parse.c` / `.h`: Custom HTTP request parser library.
* `blocked.txt`: List of domains to block.
* `server.log`: Auto-generated log file.
* `Makefile`: Compilation script.

## ⚡ How to Run

1.  **Compile the project:**
    ```bash
    gcc -o proxy proxy_server_with_cache.c proxy_parse.c -lpthread
    ```

2.  **Run the server:**
    ```bash
    ./proxy 8080
    ```

3.  **Configure Browser:**
    * Set Manual Proxy to `127.0.0.1` and Port `8080`.
    * Enable "Use this proxy for HTTPS".

## 🧪 Usage Examples

* **Access Allowed Site:** `www.google.com` -> (Loads via HTTPS Tunnel)
* **Access Blocked Site:** `www.facebook.com` -> (Returns "403 Access Denied")
* **Check Logs:** `cat server.log`