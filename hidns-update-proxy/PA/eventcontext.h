#ifndef EVENT_CONTEXT_H
#define EVENT_CONTEXT_H

#include <openssl/ssl.h>

#include "updatemsgfmt.h"

// 
typedef struct session_cmdlist
{
    int verify_fd;
    unsigned short verify_id;
    hidns_update_command *cmd;
    struct session_cmdlist *next;
} session_cmdlist_t;

// context to store the session arguments
typedef struct session_ctx
{
    int clientfd;
    int reserved;
    session_cmdlist_t* cmdbuf;
    SSL* ssl;
} session_ctx_t;

// userepolldata to determine the state transfer
typedef struct user_epolldata
{
    int eventfd;
    int epollfd;
    int eventtype;
    void *ctx;
    // session_ctx_t ctx;
    // void (*cb) (int sockfd, session_ctx_t* ctx);
    void (*cb) (void *args);
} user_epolldata_t;

void session_cmdlist_push(session_ctx_t *ctx, const int vrfd, const unsigned short vrid, hidns_update_command *cmd);
hidns_update_command* session_cmdlist_pop(session_ctx_t *ctx, const int vrfd, unsigned short *vrid);
void session_cmdlist_free(session_ctx_t *ctx);

#endif