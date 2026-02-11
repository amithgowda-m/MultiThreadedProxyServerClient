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
#define MAX_RULES 100           // Max lines per config file
#define MAX_RULE_LEN 100        // Max length of a rule

// ANSI Colors
#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define CYAN "\033[0;36m"
#define YELLOW "\033[0;33m"
#define MAGENTA "\033[0;35m"
#define RESET "\033[0m"

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

// [DYNAMIC CONFIG] Global Arrays to hold rules
char blocked_domains[MAX_RULES][MAX_RULE_LEN];
int blocked_count = 0;

char waf_signatures[MAX_RULES][MAX_RULE_LEN];
int waf_count = 0;

char dlp_extensions[MAX_RULES][MAX_RULE_LEN];
int dlp_count = 0;

char qos_domains[MAX_RULES][MAX_RULE_LEN];
int qos_count = 0;

// --- Function Prototypes ---
void load_configs(); // [NEW] Loads all txt files
cache_element* find(char* url);
int add_cache_element(char* data, int size, char* url);
void remove_cache_element();
void log_event(char* client_ip, char* url, char* event, char* color);
void url_decode(char* src, char* dest);
int inspect_waf(char* url);
int inspect_dlp(char* url); 
int check_qos_throttle(char* host); 
int check_blacklist(char* hostname);
int handle_request(int clientSocket, ParsedRequest *request, char *tempReq, char* client_ip);
int handle_https_request(int clientSocket, ParsedRequest *request, char* client_ip);
int connectRemoteServer(char* host_addr, int port_num);

// --- Global Variables ---
int port_number = 8080;
pthread_t tid[MAX_CLIENTS];
sem_t seamaphore;
pthread_mutex_t lock;       
pthread_mutex_t log_lock;   

cache_element* head;
int cache_size = 0;

#define MAX_SIZE 200*(1<<20)
#define MAX_ELEMENT_SIZE 10*(1<<20)

// --- Helper Functions ---

// [NEW] Configuration Loader
void load_file_to_array(char* filename, char array[MAX_RULES][MAX_RULE_LEN], int* count) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        printf("%s[WARNING] Could not open %s. Creating empty file.%s\n", YELLOW, filename, RESET);
        fp = fopen(filename, "w"); // Create if missing
        fclose(fp);
        return;
    }
    char line[MAX_RULE_LEN];
    *count = 0;
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = 0; // Strip newline
        if (strlen(line) > 1 && *count < MAX_RULES) {
            strcpy(array[*count], line);
            (*count)++;
        }
    }
    fclose(fp);
    printf("Loaded %d rules from %s\n", *count, filename);
}

void load_configs() {
    printf("\n%s--- LOADING CONFIGURATION ---%s\n", CYAN, RESET);
    load_file_to_array("blocked.txt", blocked_domains, &blocked_count);
    load_file_to_array("waf_rules.txt", waf_signatures, &waf_count);
    load_file_to_array("dlp_rules.txt", dlp_extensions, &dlp_count);
    load_file_to_array("qos_rules.txt", qos_domains, &qos_count);
    printf("%s--- CONFIGURATION LOADED ---%s\n\n", CYAN, RESET);
}

void url_decode(char* src, char* dest) {
    char *p = src;
    char code[3] = {0};
    unsigned long val;
    while(*p) {
        if(*p == '%') {
            memcpy(code, ++p, 2);
            val = strtoul(code, NULL, 16);
            *dest++ = (char)val;
            p += 2;
        } else if(*p == '+') {
            *dest++ = ' ';
            p++;
        } else {
            *dest++ = *p++;
        }
    }
    *dest = '\0';
}

int check_blacklist(char* hostname) {
    for (int i = 0; i < blocked_count; i++) {
        if (strstr(hostname, blocked_domains[i]) != NULL) return 1;
    }
    return 0;
}

int inspect_dlp(char* url) {
    if (url == NULL) return 0;
    int len = strlen(url);
    for (int i = 0; i < dlp_count; i++) {
        int ext_len = strlen(dlp_extensions[i]);
        if (len > ext_len) {
            if (strcasecmp(url + len - ext_len, dlp_extensions[i]) == 0) return 1; 
        }
    }
    return 0;
}

int check_qos_throttle(char* host) {
    if (host == NULL) return 0;
    for (int i = 0; i < qos_count; i++) {
        if (strstr(host, qos_domains[i]) != NULL) return 1; 
    }
    return 0;
}

int inspect_waf(char* url) {
    if (url == NULL) return 0;
    
    char decoded_url[MAX_BYTES];
    url_decode(url, decoded_url);
    
    char lower_url[MAX_BYTES];
    int len = strlen(decoded_url);
    if (len >= MAX_BYTES) len = MAX_BYTES - 1;
    for(int i = 0; i < len; i++) lower_url[i] = tolower(decoded_url[i]);
    lower_url[len] = '\0';
    
    for (int i = 0; i < waf_count; i++) {
        if (strstr(lower_url, waf_signatures[i]) != NULL) return 1;
    }
    return 0;
}

void log_event(char* client_ip, char* url, char* event, char* color) {
    printf("%s[%s] %s | %s%s\n", color, event, client_ip, url, RESET);
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

    fd_set readfds;
    int max_fd = (clientSocket > remoteSocketID) ? clientSocket : remoteSocketID;

    while(1) {
        FD_ZERO(&readfds);
        FD_SET(clientSocket, &readfds);
        FD_SET(remoteSocketID, &readfds);
        
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

void* thread_fn(void* socketNew) {
    sem_wait(&seamaphore); 
    int socket = *(int*)socketNew;
    free(socketNew); 
    
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    getpeername(socket, (struct sockaddr *)&addr, &addr_size);
    char *client_ip = inet_ntoa(addr.sin_addr);

    int len;
    char *buffer = (char*)calloc(MAX_BYTES, sizeof(char));
    len = recv(socket, buffer, MAX_BYTES, 0);
    
    struct ParsedRequest* request = ParsedRequest_create();
    if (len > 0 && ParsedRequest_parse(request, buffer, len) >= 0) {
        
        if (request->host && check_blacklist(request->host)) {
            log_event(client_ip, request->host, "BLACKLIST BLOCKED", RED);
            sendErrorMessage(socket, 403, "Access Denied: Domain is Blacklisted");
            goto cleanup;
        }

        if (request->path && inspect_dlp(request->path)) {
            log_event(client_ip, request->path, "DLP BLOCK (.exe/.sh)", RED);
            sendErrorMessage(socket, 403, "File Download Blocked by IT Policy");
            goto cleanup;
        }

        if ((request->host && inspect_waf(request->host)) || (request->path && inspect_waf(request->path))) {
            log_event(client_ip, request->host, "WAF BLOCK (Attack)", RED);
            sendErrorMessage(socket, 403, "Malicious Request Detected");
            goto cleanup;
        }

        if (strcmp(request->method, "CONNECT") == 0) {
            log_event(client_ip, request->host, "HTTPS TUNNEL", GREEN);
            handle_https_request(socket, request, client_ip); 
        } else {
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
    sem_post(&seamaphore);
    return NULL;
}

int main(int argc, char * argv[]) {
    int client_socketId; 
    struct sockaddr_in server_addr, client_addr; 
    socklen_t client_len;

    sem_init(&seamaphore, 0, MAX_CLIENTS); 
    pthread_mutex_init(&lock, NULL); 
    pthread_mutex_init(&log_lock, NULL); 

    // [NEW] Load Rules at Startup
    load_configs(); 

    if (argc == 2) port_number = atoi(argv[1]);
    else { printf("Usage: ./proxy <port>\n"); exit(1); }

    printf("\n%sENTERPRISE PROXY SERVER STARTED ON %d%s\n", CYAN, port_number, RESET);
    printf("%sWAF, DLP, BLACKLIST: LOADED FROM FILES%s\n", GREEN, RESET);
    
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
        int *client_sock_ptr = malloc(sizeof(int));
        *client_sock_ptr = client_socketId;
        pthread_create(&tid[i++], NULL, thread_fn, (void*)client_sock_ptr); 
    }
    return 0;
}

// --- Cache Implementation (Unchanged) ---
cache_element* find(char* url) {
    cache_element* site = NULL;
    pthread_mutex_lock(&lock);
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
    pthread_mutex_unlock(&lock);
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