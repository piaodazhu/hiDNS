#ifndef HIDNS_EVENTS
#define HIDNS_EVENTS

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <arpa/nameser_compat.h>
#include <sys/time.h>
#include "events.h"
#include "rkt.h"
#include "ins_msgformat.h"
#include "ins_prefix.h"
#include "ins_cache.h"
#include "dns_utils.h"
// #include "coworker.h"

/* context states */
#define F_UNUSED 0     /* unused */
#define F_CONNECTING 1 /* connect() in progress */
#define F_SENDING 2    /* writing */
#define F_READING 4    /* reading */
#define F_DONE 8       /* all done */
#define F_PROXY 16    /* temperary proxy */

#define DEFAULT_BUF_SIZE 8
#define MAX_SOCK_CTXNUM 1000

typedef struct hidns_sock_ctx hidns_sock_ctx_t;
typedef struct timeval timeval_t;

struct hidns_sock_ctx
{
	hidns_event_ops_t ops;
	int fd;
	struct sockaddr clientaddr;
	int socklen;

	uint8_t query_buf[INS_BUFMAXSIZE];
	int query_len;
	uint8_t answer_buf[INS_BUFMAXSIZE];
	int answer_len;

	uint8_t dname_buf[INS_PFXMAXSIZE];
	int dname_ptr;
	int dname_cnum;

	timeval_t lifetime;
	unsigned int state;
	hidns_sock_ctx_t *listenctx;
};


extern hidns_sock_ctx_t *g_ctx_array;
// extern hidns_sock_ctx_t listenctx;
extern int g_timeout;
// extern char g_debug[64];

// bindmod: 1: bindlocal, 2: bindremote, 0: no bind
int hidns_open_udp_socket(int bindmod, const struct sockaddr *addr, socklen_t len);

timeval_t hidns_timer_add_long(timeval_t a, long b);

timeval_t hidns_timer_add_long(timeval_t a, long b);

timeval_t hidns_timer_sub(timeval_t a, timeval_t b);

int hidns_timer_cmp(timeval_t a, timeval_t b);

int hidns_listenctx_recv(void *arg);

int hidns_listenctx_send(void *arg);

int hidns_localctx_recv(void *arg);

int hidns_localctx_send(void *arg);

int hidns_remotectx_recv(void *arg);

int hidns_remotectx_send(void *arg);

int fetch_signature(void *arg);

int receive_signature(void *arg);

#endif