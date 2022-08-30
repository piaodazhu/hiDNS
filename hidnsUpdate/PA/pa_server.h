#ifndef PA_SERVER_H
#define PA_SERVER_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <pthread.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/wait.h>

#include "eventcontext.h"
#include "updatemsgtools.h"
#include "verifystruct.h"
#include "workqueue.h"
#include "asyncverify.h"
#include "prefixtrie.h"

#define SERVER_PREFIX		"/icn/bit/"
#define SERVER_PKEYFNAME	"private.key"
#define SERVER_CERTFNAME	"cert.pem"
#define PREFIX_DUMPFNAME	".icn_bit.dump"
#define SERVER_PORT		1038
#define SERVER_SSL_PORT		1039
#define SERVER_IP		"127.0.0.1"
#define MAX_EPOLLSIZE		1000
#define MAX_BUFSIZE		4096
#define EPOLL_TIMEOUT		2000
#define TIME_SUB_MS(tv1, tv2) ((tv1.tv_sec - tv2.tv_sec) * 1000 + (tv1.tv_usec - tv2.tv_usec) / 1000)

#define DEBUG_NONE 0
#define DEBUG_PRINT 1
#define DEBUG_LOG 2

#define ntySetNonblock(fd) {	\
	int flags;	\
	flags = fcntl(fd, F_GETFL, 0);	\
	flags |= O_NONBLOCK;	\
	fcntl(fd, F_SETFL, flags);	\
}

#define ntySetReUseAddr(fd) {	\
	int reuse = 1;	\
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse));	\
}

void debugInfo(const char *format, ...);

int server_prefixtrie_init();
SSL_CTX* server_sslctx_init();

session_ctx_t* session_accept(int __listenfd, SSL_CTX* sslctx);
void session_close(session_ctx_t *__sctx);
int session_readn(session_ctx_t *__sctx, void *__buf, size_t __nbytes);
int session_writen(session_ctx_t *__sctx, const void *__buf, size_t __nbytes);

void cb_readfromvalidator(void *args);
void cb_nsupdaterecv(void *args);
void cb_readfromclient(void *args);
void *eventloop_thread(void *arg);
void *nsupdater_thread(void *arg);

#endif