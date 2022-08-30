#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

// #include <sys/epoll.h>
// #include <pthread.h>

#include "ipsock.h"
#include "loadconf.h"
#include "peccache.h"
#include "eventsys.h"
#include "hidns_events.h"

int g_stop;  /* 1: running   0: stop */

void sig_handler(int signo)
{
    switch (signo) {
    case SIGINT:
    case SIGTERM:
        g_stop = 1;
        break;

    default:
        break;
    }
}

// void* helper(void *arg) {
// 	hidns_sock_ctx_t *listenctx = arg;
// 	int epfd = epoll_create(1);
// 	struct epoll_event ev;
// 	ev.events = EPOLLIN || EPOLLET;
// 	ev.data.ptr = listenctx;
// 	epoll_ctl(epfd, EPOLL_CTL_ADD, listenctx->fd, &ev);
// 	int i, nevent;
// 	struct epoll_event events[100];
// 	printf("helper loop start\n");
// 	while (1) {
// 		nevent = epoll_wait(epfd, events, 100, -1);
// 		for (i = 0; i < nevent; i++) {
// 			hidns_sock_ctx_t *ctx = events[i].data.ptr;
// 			ctx->ops.recv((void*)ctx);
// 		}
// 	}
// 	pthread_exit(NULL);
// }

int hidns_sockctx_init()
{
	hidns_sock_ctx_t *listenctx = (hidns_sock_ctx_t*)malloc(sizeof(hidns_sock_ctx_t));
	listenctx->fd = hidns_open_udp_socket(1, (const struct sockaddr*)&GLOBAL_LOCALADDR, sizeof(GLOBAL_LOCALADDR));
	listenctx->ops.send = hidns_listenctx_send;
	listenctx->ops.recv = hidns_listenctx_recv;
	listenctx->state = F_READING;
	listenctx->listenctx = listenctx;
	hidns_eventsys_set_fd(listenctx->fd, MOD_RD, listenctx->listenctx);
	// pthread_t pid;
	// pthread_create(&pid, NULL, helper, listenctx);

	// still need initialize all ctx
	g_ctx_array = calloc(MAX_SOCK_CTXNUM, sizeof(hidns_sock_ctx_t));
	if (g_ctx_array == NULL) {
		fprintf(stderr, "Error memory low");
		exit(-1);
	}

	g_timeout = 500; // ms

	int i;
	hidns_sock_ctx_t *ctx;
	for (i = 0; i < MAX_SOCK_CTXNUM; i++) {
		ctx = &g_ctx_array[i];
		ctx->fd = -1;
		ctx->listenctx = listenctx;
		ctx->ops.send = NULL;
		ctx->ops.recv = NULL;
		ctx->state = F_UNUSED;
	}

	return 0;
}

static int hidns_process_timeout_query()
{
    int       i;
    hidns_sock_ctx_t *ctx;
    timeval_t now, diff;

    /* Deal with timeout */
    gettimeofday(&now, NULL);
    for (i = 0; i < MAX_SOCK_CTXNUM ; i++) {

        ctx = &g_ctx_array[i];

        if (ctx->state == F_UNUSED) {
            continue;
        }

        if (hidns_timer_cmp(now, ctx->lifetime) > 0) {
            /* delete timeouted context */
            if (ctx->state == F_SENDING) {
                hidns_eventsys_clear_fd(ctx->fd, MOD_WR);
            } else if (ctx->state == F_READING) {
                hidns_eventsys_clear_fd(ctx->fd, MOD_RD);
            }

            close(ctx->fd);
            ctx->state = F_UNUSED;
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
	ins_connect_cache();
	openlog("ins-server", LOG_CONS | LOG_PID, 0);
	char *configFile;
	if (argc == 1) {
		if (access("config.json", R_OK) != -1)
			configFile = "config.json";
		else if (access("../config.json", R_OK) != -1)
			configFile = "../config.json";
		else if (access("/etc/ins-server/config.json", R_OK) != -1)
			configFile = "/etc/ins-server/config.json";
		else {
#ifdef	INSSLOG_PRINT
			printf("[x] can't find config.json. exit.\n");
#endif
#ifdef	INSSLOG_SYSLOG
			syslog(LOG_ERR, "can't find config.json. exit.\n");
#endif
			exit(1);
		}

	}
	else if (argc == 3 && strlen(argv[1]) == 2 && argv[1][0] == '-' && argv[1][1] == 'c') {
		configFile = argv[2];
	}
	load_conf_json(configFile);	

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	if (hidns_set_event_sys() == -1) {
		return -1;
	}

	if (hidns_eventsys_init() == -1) {
		return -1;
	}

	if (hidns_sockctx_init() == -1) {
		return -1;
	}



#ifdef	INSSLOG_PRINT
			printf("[+] start UDP server...\n");
#endif
#ifdef	INSSLOG_SYSLOG
			syslog(LOG_ERR, "[+] start UDP server...\n");
#endif

	while (g_stop == 0) {
		hidns_eventsys_dispatch(g_timeout);
		hidns_process_timeout_query();
	}
	ins_disconnect_cache();
	return 0;
}