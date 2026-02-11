# Enterprise Multi-Threaded Proxy Server

A high-performance HTTP/HTTPS proxy server implemented in C. It features a custom Web Application Firewall (WAF), Data Loss Prevention (DLP), Traffic Shaping (QoS), and In-Memory Caching.

## 🚀 Features
- **Multi-Threading:** Handles 400+ concurrent clients using `pthread` and Semaphores.
- **WAF (Security):** Blocks SQL Injection (`union select`) and XSS (`<script>`) attacks.
- **DLP (Policy):** Prevents downloading executable files (`.exe`, `.sh`).
- **QoS (Traffic Shaping):** Throttles bandwidth for video sites (YouTube, Netflix).
- **Caching:** LRU (Least Recently Used) Cache implementation for faster browsing.
- **Dynamic Config:** Loads rules from text files without recompiling.

## 🛠️ Setup & Compilation
1. Create configuration files:
   ```bash
   echo "facebook.com" > blocked.txt
   echo "union select" > waf_rules.txt
   echo ".exe" > dlp_rules.txt
   echo "googlevideo.com" > qos_rules.txt