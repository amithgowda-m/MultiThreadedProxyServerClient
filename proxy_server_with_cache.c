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
#include <sys/select.h> // Required for I/O Multiplexing (HTTPS)

#define MAX_BYTES 4096          
#define MAX_CLIENTS 400         
#define MAX_SIZE 200*(1<<20)    
#define MAX_ELEMENT_SIZE 10*(1<<20) 
#define LOCK_FILE "server.log"
#define BLOCKED_FILE "blocked.txt"

typedef struct ParsedRequest ParsedRequest;
typedef struct cache_element cache_element;

struct cache_element {
    char* data;
    int len;
    char* url;
    time_t lru_time_track;
    cache_element* next;
};

// --- Function Prototypes ---
cache_element* find(char* url);
int add_cache_element(char* data, int size, char* url);
void remove_cache_element();
void log_message(char* client_ip, char* url, int status_code);
int check_blacklist(char* hostname);
int handle_request(int clientSocket, ParsedRequest *request, char *tempReq);
int handle_https_request(int clientSocket, ParsedRequest *request);
int connectRemoteServer(char* host_addr, int port_num);

// --- Global Variables ---
int port_number = 8080;
int proxy_socketId;
pthread_t tid[MAX_CLIENTS];
sem_t seamaphore;
pthread_mutex_t lock;       
pthread_mutex_t log_lock;   

cache_element* head;
int cache_size = 0;

// --- Helper Functions ---

void log_message(char* client_ip, char* url, int status_code) {
    pthread_mutex_lock(&log_lock);
    FILE *fp = fopen(LOCK_FILE, "a");
    if (fp) {
        time_t now = time(NULL);
        char *time_str = ctime(&now);
        time_str[strlen(time_str)-1] = '\0'; 
        fprintf(fp, "[%s] IP: %s | Status: %d | URL: %s\n", time_str, client_ip, status_code, url ? url : "-");
        fclose(fp);
    }
    pthread_mutex_unlock(&log_lock);
}

int check_blacklist(char* hostname) {
    FILE *fp = fopen(BLOCKED_FILE, "r");
    if (!fp) return 0;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = 0; 
        if (strlen(line) > 0 && strstr(hostname, line) != NULL) {
            fclose(fp);
            return 1; 
        }
    }
    fclose(fp);
    return 0;
}

int sendErrorMessage(int socket, int status_code) {
    char str[1024];
    char currentTime[50];
    time_t now = time(0);
    struct tm data = *gmtime(&now);
    strftime(currentTime, sizeof(currentTime), "%a, %d %b %Y %H:%M:%S %Z", &data);

    switch(status_code) {
        case 400: snprintf(str, sizeof(str), "HTTP/1.1 400 Bad Request\r\nContent-Length: 95\r\nConnection: keep-alive\r\nContent-Type: text/html\r\nDate: %s\r\nServer: Proxy/1.0\r\n\r\n<HTML><HEAD><TITLE>400 Bad Request</TITLE></HEAD>\n<BODY><H1>400 Bad Request</H1>\n</BODY></HTML>", currentTime); break;
        case 403: snprintf(str, sizeof(str), "HTTP/1.1 403 Forbidden\r\nContent-Length: 112\r\nContent-Type: text/html\r\nConnection: keep-alive\r\nDate: %s\r\nServer: Proxy/1.0\r\n\r\n<HTML><HEAD><TITLE>403 Forbidden</TITLE></HEAD>\n<BODY><H1>403 Forbidden</H1><br>Access Denied by Proxy\n</BODY></HTML>", currentTime); break;
        case 404: snprintf(str, sizeof(str), "HTTP/1.1 404 Not Found\r\nContent-Length: 91\r\nContent-Type: text/html\r\nConnection: keep-alive\r\nDate: %s\r\nServer: Proxy/1.0\r\n\r\n<HTML><HEAD><TITLE>404 Not Found</TITLE></HEAD>\n<BODY><H1>404 Not Found</H1>\n</BODY></HTML>", currentTime); break;
        case 500: snprintf(str, sizeof(str), "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 115\r\nConnection: keep-alive\r\nContent-Type: text/html\r\nDate: %s\r\nServer: Proxy/1.0\r\n\r\n<HTML><HEAD><TITLE>500 Internal Server Error</TITLE></HEAD>\n<BODY><H1>500 Internal Server Error</H1>\n</BODY></HTML>", currentTime); break;
        case 501: snprintf(str, sizeof(str), "HTTP/1.1 501 Not Implemented\r\nContent-Length: 103\r\nConnection: keep-alive\r\nContent-Type: text/html\r\nDate: %s\r\nServer: Proxy/1.0\r\n\r\n<HTML><HEAD><TITLE>501 Not Implemented</TITLE></HEAD>\n<BODY><H1>501 Not Implemented</H1>\n</BODY></HTML>", currentTime); break;
        case 505: snprintf(str, sizeof(str), "HTTP/1.1 505 HTTP Version Not Supported\r\nContent-Length: 125\r\nConnection: keep-alive\r\nContent-Type: text/html\r\nDate: %s\r\nServer: Proxy/1.0\r\n\r\n<HTML><HEAD><TITLE>505 HTTP Version Not Supported</TITLE></HEAD>\n<BODY><H1>505 HTTP Version Not Supported</H1>\n</BODY></HTML>", currentTime); break;
        default: return -1;
    }
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

// --- NEW FEATURE: HTTPS Tunneling (COMPLEXITY BOOSTER) ---
int handle_https_request(int clientSocket, ParsedRequest *request) {
    char *buf = (char*)malloc(MAX_BYTES);
    int server_port = 443; // Default HTTPS port
    if(request->port != NULL) server_port = atoi(request->port);

    // 1. Connect to the remote server
    int remoteSocketID = connectRemoteServer(request->host, server_port);
    if(remoteSocketID < 0) {
        free(buf);
        return -1;
    }

    // 2. Send "200 Connection Established" back to the client
    // This tells the browser: "Tunnel is ready, start sending encrypted data!"
    char *success_msg = "HTTP/1.1 200 Connection Established\r\n\r\n";
    send(clientSocket, success_msg, strlen(success_msg), 0);

    // 3. Bidirectional Data Transfer using select() (Multiplexing)
    fd_set readfds;
    int max_fd = (clientSocket > remoteSocketID) ? clientSocket : remoteSocketID;
    
    while(1) {
        FD_ZERO(&readfds);
        FD_SET(clientSocket, &readfds);
        FD_SET(remoteSocketID, &readfds);

        // Wait for activity on either socket
        if(select(max_fd + 1, &readfds, NULL, NULL, NULL) < 0) {
            break;
        }

        // If data received from client -> send to server
        if(FD_ISSET(clientSocket, &readfds)) {
            int len = recv(clientSocket, buf, MAX_BYTES, 0);
            if(len <= 0) break;
            send(remoteSocketID, buf, len, 0);
        }

        // If data received from server -> send to client
        if(FD_ISSET(remoteSocketID, &readfds)) {
            int len = recv(remoteSocketID, buf, MAX_BYTES, 0);
            if(len <= 0) break;
            send(clientSocket, buf, len, 0);
        }
    }

    free(buf);
    close(remoteSocketID);
    return 0;
}

int handle_request(int clientSocket, ParsedRequest *request, char *tempReq) {
    char *buf = (char*)malloc(sizeof(char)*MAX_BYTES);
    strcpy(buf, "GET ");
    strcat(buf, request->path);
    strcat(buf, " ");
    strcat(buf, request->version);
    strcat(buf, "\r\n");

    size_t len = strlen(buf);

    if (ParsedHeader_set(request, "Connection", "close") < 0) printf("set header key not work\n");
    if (ParsedHeader_get(request, "Host") == NULL) {
        if (ParsedHeader_set(request, "Host", request->host) < 0) printf("Set \"Host\" header key not working\n");
    }

    if (ParsedRequest_unparse_headers(request, buf + len, (size_t)MAX_BYTES - len) < 0) printf("unparse failed\n");

    int server_port = 80;
    if (request->port != NULL) server_port = atoi(request->port);

    int remoteSocketID = connectRemoteServer(request->host, server_port);
    if (remoteSocketID < 0) {
        free(buf);
        return -1;
    }

    send(remoteSocketID, buf, strlen(buf), 0);
    bzero(buf, MAX_BYTES);

    int bytes_send = recv(remoteSocketID, buf, MAX_BYTES-1, 0);
    char *temp_buffer = (char*)malloc(sizeof(char)*MAX_BYTES);
    int temp_buffer_size = MAX_BYTES;
    int temp_buffer_index = 0;

    while (bytes_send > 0) {
        send(clientSocket, buf, bytes_send, 0);
        for (int i = 0; i < bytes_send; i++) {
            temp_buffer[temp_buffer_index] = buf[i];
            temp_buffer_index++;
        }
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

int checkHTTPversion(char *msg) {
    if (strncmp(msg, "HTTP/1.1", 8) == 0) return 1;
    if (strncmp(msg, "HTTP/1.0", 8) == 0) return 1;
    return -1;
}

void* thread_fn(void* socketNew) {
    sem_wait(&seamaphore); 
    int socket = *(int*)socketNew;
    free(socketNew); 
    
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    getpeername(socket, (struct sockaddr *)&addr, &addr_size);
    char *client_ip = inet_ntoa(addr.sin_addr);

    int bytes_send_client, len;
    char *buffer = (char*)calloc(MAX_BYTES, sizeof(char));
    
    bytes_send_client = recv(socket, buffer, MAX_BYTES, 0);
    
    while (bytes_send_client > 0) {
        len = strlen(buffer);
        if (strstr(buffer, "\r\n\r\n") == NULL) {   
            bytes_send_client = recv(socket, buffer + len, MAX_BYTES - len, 0);
        } else {
            break;
        }
    }

    char *tempReq = (char*)malloc(strlen(buffer)*sizeof(char)+1);
    strcpy(tempReq, buffer);
    
    struct ParsedRequest* request = ParsedRequest_create();
    int parsed_success = ParsedRequest_parse(request, buffer, strlen(buffer));

    if (parsed_success >= 0) {
        // [CHECK] Blacklist (Works for both HTTP and HTTPS now!)
        if (request->host && check_blacklist(request->host)) {
            printf("BLOCKED: %s\n", request->host);
            sendErrorMessage(socket, 403);
            log_message(client_ip, request->host, 403);
            goto cleanup;
        }

        // [CHECK] HTTPS (CONNECT Method)
        if (strcmp(request->method, "CONNECT") == 0) {
            printf("HTTPS TUNNEL: %s\n", request->host);
            log_message(client_ip, request->host, 200);
            handle_https_request(socket, request);
            goto cleanup;
        }

        // [CHECK] Cache (Only for HTTP)
        struct cache_element* temp = find(tempReq);
        if (temp != NULL) {
            send(socket, temp->data, temp->len, 0);
            printf("CACHE HIT: %s\n", request->host);
            log_message(client_ip, request->host, 200);
        } else {
            if (!strcmp(request->method, "GET")) {
                if (request->host && request->path && (checkHTTPversion(request->version) == 1)) {
                    printf("HTTP FETCH: %s\n", request->host);
                    if (handle_request(socket, request, tempReq) == -1) {
                        sendErrorMessage(socket, 500);
                    } else {
                        log_message(client_ip, request->host, 200);
                    }
                } else {
                    sendErrorMessage(socket, 500);
                }
            } else {
                printf("Method not supported: %s\n", request->method);
            }
        }
    } else {
        printf("Parsing failed\n");
    }

cleanup:
    ParsedRequest_destroy(request);
    shutdown(socket, SHUT_RDWR);
    close(socket);
    free(buffer);
    free(tempReq);
    sem_post(&seamaphore);
    return NULL;
}

int main(int argc, char * argv[]) {
    int client_socketId, client_len; 
    struct sockaddr_in server_addr, client_addr; 

    sem_init(&seamaphore, 0, MAX_CLIENTS); 
    pthread_mutex_init(&lock, NULL); 
    pthread_mutex_init(&log_lock, NULL); 

    if (argc == 2) {
        port_number = atoi(argv[1]);
    } else {
        printf("Usage: ./proxy <port_no>\n");
        exit(1);
    }

    printf("Starting Proxy Server on Port %d\n", port_number);

    proxy_socketId = socket(AF_INET, SOCK_STREAM, 0);
    if (proxy_socketId < 0) {
        perror("Failed to create socket");
        exit(1);
    }

    int reuse = 1;
    if (setsockopt(proxy_socketId, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0) 
        perror("setsockopt(SO_REUSEADDR) failed\n");

    bzero((char*)&server_addr, sizeof(server_addr));  
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port_number); 
    server_addr.sin_addr.s_addr = INADDR_ANY; 

    if (bind(proxy_socketId, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Port is not free");
        exit(1);
    }

    if (listen(proxy_socketId, MAX_CLIENTS) < 0) {
        perror("Error while Listening");
        exit(1);
    }

    int i = 0;
    while (1) {
        bzero((char*)&client_addr, sizeof(client_addr));           
        client_len = sizeof(client_addr); 
        client_socketId = accept(proxy_socketId, (struct sockaddr*)&client_addr, (socklen_t*)&client_len);
        
        if (client_socketId < 0) {
            fprintf(stderr, "Error in Accepting connection !\n");
            continue;
        }

        int *client_sock_ptr = malloc(sizeof(int));
        *client_sock_ptr = client_socketId;
        pthread_create(&tid[i], NULL, thread_fn, (void*)client_sock_ptr); 
        i++; 
    }
    close(proxy_socketId);                                  
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
    if (element_size > MAX_ELEMENT_SIZE) {
        pthread_mutex_unlock(&lock);
        return 0;
    }
    while (cache_size + element_size > MAX_SIZE) {
        pthread_mutex_unlock(&lock); 
        remove_cache_element();
        pthread_mutex_lock(&lock);   
    }
    cache_element* element = (cache_element*)malloc(sizeof(cache_element));
    element->data = (char*)malloc(size + 1);
    strcpy(element->data, data); 
    element->url = (char*)malloc(1 + (strlen(url) * sizeof(char)));
    strcpy(element->url, url);
    element->lru_time_track = time(NULL);
    element->next = head; 
    element->len = size;
    head = element;
    cache_size += element_size;
    pthread_mutex_unlock(&lock);
    return 1;
}