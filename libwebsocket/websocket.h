#ifndef WEBSOCKET
#define WEBSOCKET

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/epoll.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

#include "../crypto/sha1.h"
#include "../crypto/base64_encoder.h"

#define SIZE 1024

typedef struct __websocket websocket_t;

typedef size_t (*ws_on_recv_cb)(websocket_t *ws);
typedef size_t (*ws_on_send_cb)(websocket_t *ws, const char* data, unsigned int len);
typedef bool (*ws_handshake_cb)(websocket_t *ws);

struct __websocket
{
    int sockfd;
    int epfd;
    char buf[SIZE];
    size_t recvd;
    bool handshake;     //是否ws握手

    ws_handshake_cb cb_hs;
    ws_on_recv_cb cb_recv;
    ws_on_send_cb cb_send;

    struct __websocket *next;
};


int ws_server_loop(const char *ip, int port);
void handle_accept(int lfd,int efd);


#endif