#include "proxy_parse.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define DEFAULT_NHDRS 8
#define MAX_REQ_LEN 65535
#define MIN_REQ_LEN 4

const char *root_dir;

struct ParsedRequest *ParsedRequest_create() {
    struct ParsedRequest *pr = (struct ParsedRequest *)malloc(sizeof(struct ParsedRequest));
    if (pr != NULL) {
        pr->buf = NULL;
        pr->method = NULL;
        pr->protocol = NULL;
        pr->host = NULL;
        pr->path = NULL;
        pr->version = NULL;
        pr->port = NULL;
        pr->buflen = 0;
        pr->headers = (struct ParsedHeader *)malloc(sizeof(struct ParsedHeader) * DEFAULT_NHDRS);
        pr->headerslen = DEFAULT_NHDRS;
        pr->headersused = 0;
    }
    return pr;
}

void ParsedRequest_destroy(struct ParsedRequest *pr) {
    if (pr->buf != NULL) free(pr->buf);
    if (pr->path != NULL) free(pr->path);
    if (pr->headerslen > 0) {
        for (size_t i = 0; i < pr->headersused; i++) {
            if (pr->headers[i].key != NULL) free(pr->headers[i].key);
            if (pr->headers[i].value != NULL) free(pr->headers[i].value);
        }
        free(pr->headers);
    }
    free(pr);
}

int ParsedHeader_set(struct ParsedRequest *pr, const char *key, const char *value) {
    struct ParsedHeader *ph;
    ParsedHeader_remove(pr, key);

    if (pr->headerslen <= pr->headersused + 1) {
        pr->headerslen *= 2;
        pr->headers = (struct ParsedHeader *)realloc(pr->headers, pr->headerslen * sizeof(struct ParsedHeader));
    }

    ph = pr->headers + pr->headersused;
    pr->headersused += 1;

    ph->key = (char *)malloc(strlen(key) + 1);
    strcpy(ph->key, key);

    if (value != NULL) {
        ph->value = (char *)malloc(strlen(value) + 1);
        strcpy(ph->value, value);
    } else {
        ph->value = NULL;
    }

    return 0;
}

struct ParsedHeader *ParsedHeader_get(struct ParsedRequest *pr, const char *key) {
    for (size_t i = 0; i < pr->headersused; i++) {
        struct ParsedHeader *ph = pr->headers + i;
        if (strcasecmp(ph->key, key) == 0) {
            return ph;
        }
    }
    return NULL;
}

int ParsedHeader_remove(struct ParsedRequest *pr, const char *key) {
    for (size_t i = 0; i < pr->headersused; i++) {
        struct ParsedHeader *ph = pr->headers + i;
        if (strcasecmp(ph->key, key) == 0) {
            free(ph->key);
            if (ph->value != NULL) free(ph->value);
            memmove(ph, ph + 1, (pr->headersused - i - 1) * sizeof(struct ParsedHeader));
            pr->headersused -= 1;
            return 0;
        }
    }
    return -1;
}

int ParsedRequest_parse(struct ParsedRequest *pr, const char *buf, int buflen) {
    char *full_addr;
    char *saveptr;
    char *index;
    char *current;

    if (pr->buf != NULL) return -1; // Already parsed

    if (buflen < MIN_REQ_LEN || buflen > MAX_REQ_LEN) return -1;

    pr->buf = (char *)malloc(buflen + 1);
    memcpy(pr->buf, buf, buflen);
    pr->buf[buflen] = '\0';
    pr->buflen = buflen;

    // Parse Request Line
    current = strtok_r(pr->buf, "\r\n", &saveptr);
    if (current == NULL) return -1;

    // 1. METHOD
    index = strchr(current, ' ');
    if (index == NULL) return -1;
    *index = '\0';
    pr->method = current;
    current = index + 1;

    // 2. URL
    index = strchr(current, ' ');
    if (index == NULL) return -1;
    *index = '\0';
    full_addr = current;
    current = index + 1;

    // 3. VERSION
    pr->version = current;

    // Parse Headers
    while ((current = strtok_r(NULL, "\r\n", &saveptr)) != NULL) {
        index = strchr(current, ':');
        if (index != NULL) {
            *index = '\0';
            ParsedHeader_set(pr, current, index + 2); 
        }
    }

    // Parse Host/Port
    if (strstr(full_addr, "http://")) {
        pr->protocol = "http";
        full_addr += 7;
    } else if (strstr(full_addr, "https://")) {
        pr->protocol = "https";
        full_addr += 8;
    } else {
        pr->protocol = "http";
    }

    char *port_ptr = strchr(full_addr, ':');
    char *path_ptr = strchr(full_addr, '/');

    if (path_ptr != NULL) {
        *path_ptr = '\0';
        pr->host = full_addr;
        pr->path = (char *)malloc(strlen(path_ptr + 1) + 2);
        sprintf(pr->path, "/%s", path_ptr + 1);
    } else {
        pr->host = full_addr;
        pr->path = (char *)malloc(2);
        strcpy(pr->path, "/");
    }

    if (port_ptr != NULL && (path_ptr == NULL || port_ptr < path_ptr)) {
        *port_ptr = '\0';
        pr->host = full_addr;
        pr->port = port_ptr + 1;
    } 

    // Set default port if missing
    if (pr->port == NULL) {
        if(strcmp(pr->method, "CONNECT") == 0) pr->port = "443";
        else pr->port = "80";
    }

    return 0;
}

int ParsedRequest_unparse(struct ParsedRequest *pr, char *buf, size_t buflen) {
    return -1;
}

int ParsedRequest_unparse_headers(struct ParsedRequest *pr, char *buf, size_t buflen) {
    if (!buf || buflen == 0) return -1;
    char *current = buf;
    size_t remaining = buflen;
    
    for (size_t i = 0; i < pr->headersused; i++) {
        int written = snprintf(current, remaining, "%s: %s\r\n", pr->headers[i].key, pr->headers[i].value);
        if (written < 0 || written >= remaining) return -1;
        current += written;
        remaining -= written;
    }
    if (remaining < 2) return -1;
    strcpy(current, "\r\n");
    return 0;
}

size_t ParsedRequest_totalLen(struct ParsedRequest *pr) {
    return 0; // Placeholder
}

void debug(const char * format, ...) {
    // Silence debug prints
}