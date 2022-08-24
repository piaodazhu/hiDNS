#ifndef EVENT_CONTEXT_H
#define EVENT_CONTEXT_H

#include <openssl/ssl.h>

#include "updatemsgfmt.h"

// 
typedef struct session_cmdlist
{
    int                     verify_fd;
    unsigned short          verify_id;
    hidns_update_command    *cmd;
    struct session_cmdlist  *next;
} session_cmdlist_t;

// context to store the session arguments
typedef struct session_ctx
{
    unsigned int        u32id;
    int                 clientfd;
    SSL*                ssl;
    session_cmdlist_t   *cmdbuf;    
} session_ctx_t;

// userepolldata to determine the state transfer
typedef struct user_epolldata
{
    int     eventfd;
    int     ac_epfd;
    int     ev_epfd;
    int     udatatype;
    void    *ctx;
    void    (*cb) (void *args);
} user_epolldata_t;

#define UDATATYPE_ACCEPT    0
#define UDATATYPE_CLIENT    1
#define UDATATYPE_TIMER     2
#define UDATATYPE_VERIFY    3

void session_cmdlist_push(session_ctx_t *ctx, const int vrfd, const unsigned short vrid, hidns_update_command *cmd);
hidns_update_command* session_cmdlist_pop(session_ctx_t *ctx, const int vrfd, unsigned short *vrid);
void session_cmdlist_free(session_ctx_t *ctx);

#endif