#ifndef IDNS_IPSOCK_H
#define IDNS_IPSOCK_H
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>

#ifndef _PERR_EXIT
#define _PERR_EXIT
// #define perr_exit(s) do { perror(s); exit(1);} while(0)
#define perr_exit(s) do { perror(s); return -1;} while(0)
#endif

struct session_args {
	struct sockaddr_in remote;
	int sockfd;
	unsigned char* buf;
	int buflen;
};

int Socket(int domain, int type, int protocol);

int Bind(int sockfd,const struct sockaddr *addr, socklen_t addrlen);

int Listen(int sockfd, int backlog);

int Accept(int sockfd,struct sockaddr *addr, socklen_t *addrlen);

int TCPstart_up(struct sockaddr_in* local, int max_connect_num);

int Connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
 
int Read(int fd, void *buf, unsigned int nbytes);
 
int Write(int fd, const void *buf, unsigned int nbytes);

#endif