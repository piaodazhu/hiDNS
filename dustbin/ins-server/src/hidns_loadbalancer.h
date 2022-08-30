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

#define FWD_DIR_NUM 2
#define MAX_MAP_SIZE 65536
#define LB_F_UNUSED 0     /* unused */
#define LB_F_ISUSED 1     /* used */
typedef struct hidns_udp_forwarder_obj hidns_udp_forwarder_obj_t;
typedef struct timeval timeval_t;

struct hidns_udp_forwarder_obj
{
	hidns_event_ops_t ops;
	int fd;
	int listenfd;
	// struct sockaddr_in clientaddr;

	// timeval_t lifetime;
	// unsigned int state;
	// hidns_sock_ctx_t *listenctx;
};

typedef struct forward_mapping_entry
{
	uint16_t flag;
	uint16_t qid;
	struct sockaddr_in clientaddr;
	timeval_t lifetime;

} forward_mapping_entry_t;

typedef struct forward_mapping_table
{
	int tabsize;
	int cur_idx;
	forward_mapping_entry_t entry[MAX_MAP_SIZE];

} forward_mapping_table_t;

int not_implement(void* arg);
int innerrecv(void* arg);
int clientrecv(void* arg);


#endif