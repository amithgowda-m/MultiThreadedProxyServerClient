#ifndef PROXY_PARSE_H
#define PROXY_PARSE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct ParsedHeader {
    char *key;
    size_t keylen;
    char *value;
    size_t valuelen;
};

struct ParsedRequest {
    char *method;
    char *protocol;
    char *host;
    char *port;
    char *path;
    char *version;
    char *buf;
    size_t buflen;
    struct ParsedHeader *headers;
    size_t headersused;
    size_t headerslen;
};

struct ParsedRequest *ParsedRequest_create();
int ParsedRequest_parse(struct ParsedRequest *pr, const char *buf, int buflen);
void ParsedRequest_destroy(struct ParsedRequest *pr);
int ParsedRequest_unparse_headers(struct ParsedRequest *pr, char *buf, size_t buflen);
int ParsedHeader_set(struct ParsedRequest *pr, const char *key, const char *value);
struct ParsedHeader *ParsedHeader_get(struct ParsedRequest *pr, const char *key);
int ParsedHeader_remove(struct ParsedRequest *pr, const char *key);

#endif