#include "proxy_parse.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/wait.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/select.h>
#include <ctype.h>

#define MAX_BYTES 4096          
#define MAX_CLIENTS 400         
#define LOCK_FILE "server.log"
#define BLOCKED_FILE "blocked.txt"

// ANSI Colors for Terminal
#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define CYAN "\033[0;36m"
#define YELLOW "\033[0;33m"
#define MAGENTA "\033[0;35m"
#define RESET "\033[0m"

// [OS CONCEPT] Process Scheduling / Sleep
// We use usleep() to voluntarily yield CPU time to simulate throttling
#define THROTTLE_DELAY_US 100000 

typedef struct ParsedRequest ParsedRequest;
typedef struct cache_element cache_element;

struct cache_element {
    char* data;
    int len;
    char* url;
    time_t lru_time_track;
    cache_element* next;
};

// [OS CONCEPT] Global Shared Resources
// These require synchronization (Locks) to prevent Race Conditions
const char *blocked_extensions[] = { ".exe", ".sh", ".bat", ".bin", ".tar.gz", NULL };
const char *throttled_domains[] = { "googlevideo.com", "netflix.com", "fbcdn.net", NULL };
const char *waf_signatures[] = { "union select", "<script>", "alert(", "../", "/etc/passwd", "drop table", NULL };

// --- Function Prototypes ---
cache_element* find(char* url);
int add_cache_element(char* data, int size, char* url);
void remove_cache_element();
void log_event(char* client_ip, char* url, char* event, char* color);
int inspect_waf(char* url);
int inspect_dlp(char* url); 
int check_qos_throttle(char* host); 
int check_blacklist(char* hostname); // [RESTORED]
int handle_request(int clientSocket, ParsedRequest *request, char *tempReq, char* client_ip);
int handle_https_request(int clientSocket, ParsedRequest *request, char* client_ip);
int connectRemoteServer(char* host_addr, int port_num);

// --- Global Variables ---
int port_number = 8080;
pthread_t tid[MAX_CLIENTS];

// [OS CONCEPT] Synchronization Primitives
sem_t seamaphore;           // Controls max active threads (Concurrency Limit)
pthread_mutex_t lock;       // Protects the Cache (Critical Section)
pthread_mutex_t log_lock;   // Protects the Log File (I/O Safety)

cache_element* head;
int cache_size = 0;

// [OS CONCEPT] Memory Management Limits
#define MAX_SIZE 200*(1<<20)        // 200MB Cache
#define MAX_ELEMENT_SIZE 10*(1<<20) // 10MB Max File

// --- Helper Functions ---

int check_blacklist(char* hostname) {
    // [OS CONCEPT] File I/O
    FILE *fp = fopen(BLOCKED_FILE, "r");
    if (!fp) return 0;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = 0; 
        if (strlen(line) > 0 && strstr(hostname, line) != NULL) {
            fclose(fp);
            return 1; // Blocked!
        }
    }
    fclose(fp);
    return 0;
}

int inspect_dlp(char* url) {
    if (url == NULL) return 0;
    int len = strlen(url);
    for (int i = 0; blocked_extensions[i] != NULL; i++) {
        int ext_len = strlen(blocked_extensions[i]);
        if (len > ext_len) {
            if (strcasecmp(url + len - ext_len, blocked_extensions[i]) == 0) return 1; 
        }
    }
    return 0;
}

int check_qos_throttle(char* host) {
    if (host == NULL) return 0;
    for (int i = 0; throttled_domains[i] != NULL; i++) {
        if (strstr(host, throttled_domains[i]) != NULL) return 1; 
    }
    return 0;
}

int inspect_waf(char* url) {
    if (url == NULL) return 0;
    char lower_url[MAX_BYTES];
    int len = strlen(url);
    if (len >= MAX_BYTES) len = MAX_BYTES - 1;
    for(int i = 0; i < len; i++) lower_url[i] = tolower(url[i]);
    lower_url[len] = '\0';
    for (int i = 0; waf_signatures[i] != NULL; i++) {
        if (strstr(lower_url, waf_signatures[i]) != NULL) return 1;
    }
    return 0;
}

void log_event(char* client_ip, char* url, char* event, char* color) {
    printf("%s[%s] %s | %s%s\n", color, event, client_ip, url, RESET);
    
    // [OS CONCEPT] Mutual Exclusion (Mutex)
    // Only one thread can write to the file at a time
    pthread_mutex_lock(&log_lock);
    FILE *fp = fopen(LOCK_FILE, "a");
    if (fp) {
        time_t now = time(NULL);
        char *time_str = ctime(&now);
        time_str[strlen(time_str)-1] = '\0'; 
        fprintf(fp, "[%s] %s | %s | %s\n", time_str, event, client_ip, url);
        fclose(fp);
    }
    pthread_mutex_unlock(&log_lock);
}

int sendErrorMessage(int socket, int status_code, char* msg) {
    char str[1024];
    snprintf(str, sizeof(str), 
        "HTTP/1.1 %d Error\r\nContent-Type: text/html\r\n\r\n"
        "<HTML><BODY><H1 style='color:red'>Proxy Error: %d</H1><h3>%s</h3></BODY></HTML>", 
        status_code, status_code, msg);
    send(socket, str, strlen(str), 0);
    return 1;
}

int connectRemoteServer(char* host_addr, int port_num) {
    // [OS CONCEPT] Sockets (IPC)
    int remoteSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (remoteSocket < 0) return -1;
    struct hostent *host = gethostbyname(host_addr);    
    if (host == NULL) return -1;
    struct sockaddr_in server_addr;
    bzero((char*)&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port_num);
    bcopy((char *)host->h_addr, (char *)&server_addr.sin_addr.s_addr, host->h_length);
    if (connect(remoteSocket, (struct sockaddr*)&server_addr, (socklen_t)sizeof(server_addr)) < 0) return -1;
    return remoteSocket;
}

int handle_https_request(int clientSocket, ParsedRequest *request, char* client_ip) {
    char *buf = (char*)malloc(MAX_BYTES);
    int server_port = 443; 
    if(request->port != NULL) server_port = atoi(request->port);

    int remoteSocketID = connectRemoteServer(request->host, server_port);
    if(remoteSocketID < 0) { free(buf); return -1; }

    char *success_msg = "HTTP/1.1 200 Connection Established\r\n\r\n";
    send(clientSocket, success_msg, strlen(success_msg), 0);

    int throttle = check_qos_throttle(request->host);
    if (throttle) log_event(client_ip, request->host, "QoS THROTTLING", MAGENTA);

    // [OS CONCEPT] I/O Multiplexing (select)
    // Monitors multiple file descriptors to see if they are ready for reading
    fd_set readfds;
    int max_fd = (clientSocket > remoteSocketID) ? clientSocket : remoteSocketID;

    while(1) {
        FD_ZERO(&readfds);
        FD_SET(clientSocket, &readfds);
        FD_SET(remoteSocketID, &readfds);
        
        // This blocks the thread until data is available on either socket
        if(select(max_fd + 1, &readfds, NULL, NULL, NULL) < 0) break;
        
        if(FD_ISSET(clientSocket, &readfds)) {
            int len = recv(clientSocket, buf, MAX_BYTES, 0);
            if(len <= 0) break;
            send(remoteSocketID, buf, len, 0);
        }
        
        if(FD_ISSET(remoteSocketID, &readfds)) {
            int len = recv(remoteSocketID, buf, MAX_BYTES, 0);
            if(len <= 0) break;
            send(clientSocket, buf, len, 0);
            
            // [OS CONCEPT] Context Switching / Sleep
            if (throttle) usleep(THROTTLE_DELAY_US); 
        }
    }
    free(buf);
    close(remoteSocketID);
    return 0;
}

int handle_request(int clientSocket, ParsedRequest *request, char *tempReq, char* client_ip) {
    char *buf = (char*)malloc(MAX_BYTES);
    strcpy(buf, "GET "); strcat(buf, request->path); strcat(buf, " "); strcat(buf, request->version); strcat(buf, "\r\n");
    size_t len = strlen(buf);
    
    ParsedHeader_set(request, "Connection", "close");
    ParsedHeader_set(request, "Host", request->host);
    ParsedRequest_unparse_headers(request, buf + len, MAX_BYTES - len);

    int server_port = 80;
    if (request->port != NULL) server_port = atoi(request->port);
    int remoteSocketID = connectRemoteServer(request->host, server_port);
    if (remoteSocketID < 0) { free(buf); return -1; }

    send(remoteSocketID, buf, strlen(buf), 0);
    bzero(buf, MAX_BYTES);
    
    int bytes_send = recv(remoteSocketID, buf, MAX_BYTES-1, 0);
    char *temp_buffer = (char*)malloc(MAX_BYTES);
    int temp_buffer_size = MAX_BYTES;
    int temp_buffer_index = 0;

    while (bytes_send > 0) {
        send(clientSocket, buf, bytes_send, 0);
        for (int i = 0; i < bytes_send; i++) { temp_buffer[temp_buffer_index++] = buf[i]; }
        if (temp_buffer_index + MAX_BYTES > temp_buffer_size) {
            temp_buffer_size += MAX_BYTES;
            char *new_ptr = realloc(temp_buffer, temp_buffer_size);
            if (!new_ptr) break;
            temp_buffer = new_ptr;
        }
        bzero(buf, MAX_BYTES);
        bytes_send = recv(remoteSocketID, buf, MAX_BYTES-1, 0);
    } 
    temp_buffer[temp_buffer_index] = '\0';
    free(buf);
    add_cache_element(temp_buffer, temp_buffer_index, tempReq); 
    free(temp_buffer);
    close(remoteSocketID);
    return 0;
}

// [OS CONCEPT] Thread Function
void* thread_fn(void* socketNew) {
    // [OS CONCEPT] Semaphores
    // Wait operation decrements semaphore; blocks if value is 0
    sem_wait(&seamaphore); 
    
    int socket = *(int*)socketNew;
    free(socketNew); // Free heap memory allocated in main
    
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    getpeername(socket, (struct sockaddr *)&addr, &addr_size);
    char *client_ip = inet_ntoa(addr.sin_addr);

    int len;
    char *buffer = (char*)calloc(MAX_BYTES, sizeof(char));
    len = recv(socket, buffer, MAX_BYTES, 0);
    
    struct ParsedRequest* request = ParsedRequest_create();
    if (len > 0 && ParsedRequest_parse(request, buffer, len) >= 0) {
        
        // 1. [RESTORED] Block List Check
        if (request->host && check_blacklist(request->host)) {
            log_event(client_ip, request->host, "BLACKLIST BLOCKED", RED);
            sendErrorMessage(socket, 403, "Access Denied: Domain is Blacklisted");
            goto cleanup;
        }

        // 2. DLP: File Extension Blocking
        if (request->path && inspect_dlp(request->path)) {
            log_event(client_ip, request->path, "DLP BLOCK (.exe/.sh)", RED);
            sendErrorMessage(socket, 403, "File Download Blocked by IT Policy");
            goto cleanup;
        }

        // 3. WAF: Security Inspection
        if ((request->host && inspect_waf(request->host)) || (request->path && inspect_waf(request->path))) {
            log_event(client_ip, request->host, "WAF BLOCK (Attack)", RED);
            sendErrorMessage(socket, 403, "Malicious Request Detected");
            goto cleanup;
        }

        // 4. HTTPS Tunneling
        if (strcmp(request->method, "CONNECT") == 0) {
            log_event(client_ip, request->host, "HTTPS TUNNEL", GREEN);
            handle_https_request(socket, request, client_ip); 
        } else {
            // 5. Caching (Reader/Writer Problem simplified)
            char *tempReq = (char*)malloc(strlen(buffer)+1);
            strcpy(tempReq, buffer);
            struct cache_element* temp = find(tempReq);
            
            if (temp != NULL) {
                send(socket, temp->data, temp->len, 0);
                printf("%s[CACHE HIT] Served from memory%s\n", CYAN, RESET);
            } else {
                 if (handle_request(socket, request, tempReq, client_ip) == -1) sendErrorMessage(socket, 500, "Internal Error");
            }
            free(tempReq);
        }
    } 
    
cleanup:
    ParsedRequest_destroy(request);
    shutdown(socket, SHUT_RDWR);
    close(socket);
    free(buffer);
    
    // [OS CONCEPT] Semaphores
    // Signal operation increments semaphore; wakes up blocked threads
    sem_post(&seamaphore);
    return NULL;
}

int main(int argc, char * argv[]) {
    int client_socketId; 
    struct sockaddr_in server_addr, client_addr; 
    socklen_t client_len;

    // [OS CONCEPT] Initialization of Sync Primitives
    sem_init(&seamaphore, 0, MAX_CLIENTS); 
    pthread_mutex_init(&lock, NULL); 
    pthread_mutex_init(&log_lock, NULL); 

    if (argc == 2) port_number = atoi(argv[1]);
    else { printf("Usage: ./proxy <port>\n"); exit(1); }

    printf("\n%s🏢 OS FINAL PROXY SERVER STARTED ON %d%s\n", CYAN, port_number, RESET);
    printf("%s🛑 LAYER 1: BLACKLIST ENABLED%s\n", RED, RESET);
    printf("%s🛡️  LAYER 2: WAF & DLP ACTIVE%s\n", GREEN, RESET);
    printf("%s📉 LAYER 3: QoS TRAFFIC SHAPING ACTIVE%s\n\n", MAGENTA, RESET);

    int proxy_socketId = socket(AF_INET, SOCK_STREAM, 0);
    int reuse = 1;
    setsockopt(proxy_socketId, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port_number); 
    server_addr.sin_addr.s_addr = INADDR_ANY; 
    bind(proxy_socketId, (struct sockaddr*)&server_addr, sizeof(server_addr));
    listen(proxy_socketId, MAX_CLIENTS);

    int i = 0;
    while (1) {
        client_len = sizeof(client_addr); 
        client_socketId = accept(proxy_socketId, (struct sockaddr*)&client_addr, &client_len);
        if (client_socketId < 0) continue;
        
        // [OS CONCEPT] Heap Memory Allocation
        // Allocate memory for socket ID to pass to thread safely
        int *client_sock_ptr = malloc(sizeof(int));
        *client_sock_ptr = client_socketId;
        
        // [OS CONCEPT] Multithreading
        // Create a new thread for every client connection
        pthread_create(&tid[i++], NULL, thread_fn, (void*)client_sock_ptr); 
    }
    return 0;
}

// --- Cache Implementation (Unchanged) ---
cache_element* find(char* url) {
    cache_element* site = NULL;
    pthread_mutex_lock(&lock); // Critical Section Entry
    if (head != NULL) {
        site = head;
        while (site != NULL) {
            if (!strcmp(site->url, url)) {
                site->lru_time_track = time(NULL);
                break;
            }
            site = site->next;
        }       
    }
    pthread_mutex_unlock(&lock); // Critical Section Exit
    return site;
}

void remove_cache_element() {
    cache_element *p, *q, *temp;
    pthread_mutex_lock(&lock);
    if (head != NULL) {
        for (q = head, p = head, temp = head; q != NULL; q = q->next) {
            if (q->lru_time_track < temp->lru_time_track) temp = q;
        }
        if (temp == head) head = head->next; 
        else {
            p = head;
            while (p->next != temp) p = p->next;
            p->next = temp->next;   
        }
        cache_size -= (temp->len + sizeof(cache_element) + strlen(temp->url) + 1);
        free(temp->data); free(temp->url); free(temp);
    } 
    pthread_mutex_unlock(&lock);
}

int add_cache_element(char* data, int size, char* url) {
    pthread_mutex_lock(&lock);
    int element_size = size + 1 + strlen(url) + sizeof(cache_element);
    if (element_size > MAX_ELEMENT_SIZE) { pthread_mutex_unlock(&lock); return 0; }
    while (cache_size + element_size > MAX_SIZE) {
        pthread_mutex_unlock(&lock); remove_cache_element(); pthread_mutex_lock(&lock);   
    }
    cache_element* element = (cache_element*)malloc(sizeof(cache_element));
    element->data = (char*)malloc(size + 1);
    strcpy(element->data, data); 
    element->url = (char*)malloc(1 + (strlen(url) * sizeof(char)));
    strcpy(element->url, url);
    element->lru_time_track = time(NULL);
    element->next = head; element->len = size; head = element;
    cache_size += element_size;
    pthread_mutex_unlock(&lock);
    return 1;
}