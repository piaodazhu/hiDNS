#ifndef IDNS_NIPSOCK_H
#define IDNS_NIPSOCK_H
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <linux/isockethdr.h>

#ifndef _PERR_EXIT
#define _PERR_EXIT
#define perr_exit(s) do { perror(s); exit(1);} while(0)
#endif

int iSocket(int domain, int type, int protocol);

int iBind(int sockfd, const struct nsockaddr *addr, socklen_t addrlen);

int iPublish(int sockfd, struct isockbuf *ibuf, size_t ibuflen);

int iUnpublish(int sockfd, char *name, size_t nlen);

int iCast(int sockfd, struct isockbuf *ibuf, size_t ibuflen, unsigned int lifetime);


int iStatus(int sockfd, struct status_info *stat_buf, 
			size_t buf_len, unsigned int flags);

int iSend(int sockfd, struct isockbuf *ibuf, size_t ibuflen, unsigned int flags);

int iTouch(int sockfd, struct touch_info *tbuf, 
			size_t tbuflen, unsigned int flags);

int iWatch(int sockfd, char* name, size_t nlen);

int iUnwatch(int sockfd, char* name, size_t nlen);

int iRequest(int sockfd, struct touch_info *tbuf, size_t tbuflen);

int iRecv(int sockfd, struct isockbuf *ibuf, size_t ibuflen, unsigned int flags);


#define IBUF_COPY_NAME		0b0001
#define IBUF_REF_NAME		0b0010
#define IBUF_COPY_DATA 		0b0100
#define IBUF_REF_DATA		0b1000

struct isockbuf* ibuf_interest_init(char* name, size_t nlen, unsigned int flags);

struct isockbuf* ibuf_data_init(char* name, size_t nlen, char* data, size_t dlen, unsigned int flags);

struct status_info* ibuf_sinfo_init(char *name, size_t nlen, unsigned int flags);

struct touch_info* ibuf_tinfo_init(char *name, size_t nlen, unsigned int flags);

int ibuf_interest_reset(struct isockbuf* ibuf, size_t nlen);

int ibuf_data_reset(struct isockbuf* ibuf, size_t nlen, size_t dlen);

int ibuf_tinfo_reset(struct touch_info* tbuf, size_t nlen, char* name);

int ibuf_sinfo_reset(struct status_info* sbuf, size_t nlen);

int ibuf_interest_free(struct isockbuf* ibuf, unsigned int flags);

int ibuf_data_free(struct isockbuf* ibuf, unsigned int flags);

int ibuf_sinfo_free(struct status_info* sbuf, unsigned int flags);

int ibuf_tinfo_free(struct touch_info* tbuf, unsigned int flags);

#endif