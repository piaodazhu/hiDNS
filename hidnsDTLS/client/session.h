#ifndef DTLS_PROXY_SESSION_H
#define DTLS_PROXY_SESSION_H

#ifdef _WIN32
#include <winsock2.h>
#include <Ws2tcpip.h>
#define in_port_t u_short
#define ssize_t int
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <pthread.h>
#endif

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "hashmap.h"

#define SSL_STATUS_HANDSHAKE 0
#define SSL_STATUS_OK        1
#define SSL_STATUS_ERR     -1

#define THREAD_STATUS_NEW 0
#define THREAD_STATUS_RUNNING 1
#define THREAD_STATUS_STOPPING  2
#define THREAD_STATUS_DEAD  3

union mysockaddr
{
	struct sockaddr_storage ss;
	struct sockaddr_in6 s6;
	struct sockaddr_in s4;
};

typedef struct transrecord
{
	unsigned int transaction_id;
	struct sockaddr_in client_addr;
} transrecord;

typedef struct session
{
	union mysockaddr server_addr;
	union mysockaddr client_addr;
	SSL *ssl;
	BIO *for_reading;
	BIO *for_writing;
	struct hashmap *transmap;
	int ssl_status;
	int thread_status;
	int handshake_finished;
	int dtls_fd;
	time_t active_time;
	int send_count;
	struct session *next;
	struct session *prev;
} session;

char addrbuf[INET6_ADDRSTRLEN];

void printList(session *session_list);
int get_session_count(session *session_list);
session *get_session(session *session_list, union mysockaddr addr);
session *add_session(session **psession_list, union mysockaddr server_addr,
union mysockaddr client_addr, SSL *ssl, BIO *for_reading,
	BIO *for_writing, int dtls_fd);
int remove_session(session **psession_list, session **psession);

#endif