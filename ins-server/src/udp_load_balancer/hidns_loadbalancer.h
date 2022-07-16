#ifndef HIDNS_LOADBALANCER_H
#define HIDNS_LOADBALANCER_H

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <netdb.h>
#include "hidns_events.h"
#include "events.h"

#define MAX_OBJ_NUM 10000
#define FWD_DIR_NUM 2
#define LB_F_UNUSED 0     /* unused */
#define LB_F_ISUSED 1     /* used */
typedef struct hidns_udp_forwarder_obj hidns_udp_forwarder_obj_t;
typedef struct timeval timeval_t;

struct hidns_udp_forwarder_obj
{
	hidns_event_ops_t ops;
	int fd;
	int listenfd;
	struct sockaddr_in clientaddr;

	timeval_t lifetime;
	unsigned int state;
	// hidns_sock_ctx_t *listenctx;
};
struct sockaddr_in server_addr;
struct sockaddr_in forward_addr[FWD_DIR_NUM];

extern hidns_udp_forwarder_obj_t *g_obj_array;
extern int g_obj_idx;
extern int g_timeout;

int not_implement(void* arg);
int innerrecv(void* arg);
int clientrecv(void* arg);


#endif