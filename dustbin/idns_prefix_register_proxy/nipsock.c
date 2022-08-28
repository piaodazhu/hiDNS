#include "nipsock.h"


int iSocket(int domain, int type, int protocol)
{
	int fd = socket(domain, type, protocol);
	if(fd == -1)
		perr_exit("iSocket() error!\n");
	return fd;
}

int iBind(int sockfd, const struct nsockaddr *addr, socklen_t addrlen)
{
	int ret = bind(sockfd, addr, addrlen);
	if(ret == -1)	
		perr_exit("iBind() error!\n");
	return ret;
}

int iPublish(int sockfd, struct isockbuf *ibuf, size_t ibuflen)
{
    int ret = publish(sockfd, ibuf, ibuflen);
    if (ret < 0)
        perr_exit("iPublish() error!\n");
    return ret;
}

int iUnpublish(int sockfd, char *name, size_t nlen)
{
    int ret = unpublish(sockfd, name, nlen);
    if (ret < 0)
        perr_exit("iUnpublish() error!\n");
    return ret;
}

int iCast(int sockfd, struct isockbuf *ibuf, size_t ibuflen, unsigned int lifetime)
{
    int ret = cast(sockfd, ibuf, ibuflen, lifetime);
    if (ret < 0)
        perr_exit("iCast() error!\n");
    return ret;
}

int iStatus(int sockfd, struct status_info *stat_buf, 
			size_t buf_len, unsigned int flags)
{
    int ret = status(sockfd, stat_buf, buf_len, flags);
    if (ret < 0)
        perr_exit("iStatus() error!\n");
    return ret;
}

int iSend(int sockfd, struct isockbuf *ibuf, size_t ibuflen, unsigned int flags)
{
    int ret = isend(sockfd, ibuf, ibuflen, flags);
    if (ret < 0)
        perr_exit("iSend() error!\n");
    return ret;
}

int iTouch(int sockfd, struct touch_info *tbuf, 
			size_t tbuflen, unsigned int flags)
{
    int ret = touch(sockfd, tbuf, tbuflen, flags);
    if (ret < 0)
        perr_exit("iTouch() error!\n");
    return ret;
}

int iWatch(int sockfd, char* name, size_t nlen)
{
    int watch_id = watch(sockfd, name, nlen);
	if (watch_id <= 0) {
		printf("[!] watch failed, err: %d \n", watch_id);
		perr_exit("iWatch() error!\n");
    }
    return watch_id;
}

int iUnwatch(int sockfd, char* name, size_t nlen)
{
    int ret = unwatch(sockfd, name, nlen);
    if (ret < 0) {
        perr_exit("iUnwatch() error!\n");
    }
    return ret;
}

int iRequest(int sockfd, struct touch_info *tbuf, size_t tbuflen)
{
    int ret = request(sockfd, tbuf, tbuflen);
    if (ret < 0)
        perr_exit("iRequest() error!\n");
    return ret;
}

int iRecv(int sockfd, struct isockbuf *ibuf, size_t ibuflen, unsigned int flags)
{
    int ret = irecv(sockfd, ibuf, ibuflen, flags);
    if (ret < 0)
        perr_exit("iRecv() error!\n");
    return ret;
}

struct isockbuf* ibuf_interest_init(char* name, size_t nlen, unsigned int flags)
{
    struct isockbuf* ibuf = (struct isockbuf*) malloc (sizeof(struct isockbuf));
    ibuf->type = TYPE_INTEREST;
    ibuf->nlen = nlen;
    if (flags & IBUF_REF_NAME) {
        ibuf->name = name;
    }
    else if (flags & IBUF_COPY_NAME) {
        int k = 16;
        while (k < nlen) k = (k << 1);
        k = (k << 1);
        ibuf->name = malloc(k);
        if (name != NULL)
            memcpy(ibuf->name, name, nlen);
    } else {
        return NULL;
    }
    return ibuf;
}

struct isockbuf* ibuf_data_init(char* name, size_t nlen, char* data, size_t dlen, unsigned int flags)
{
    struct isockbuf* ibuf = (struct isockbuf*) malloc (sizeof(struct isockbuf));
    ibuf->type = TYPE_DATA;
    ibuf->nlen = nlen;
    ibuf->dlen = dlen;
    if (flags & IBUF_REF_NAME) {
        ibuf->name = name;
    }
    else if (flags & IBUF_COPY_NAME) {
        int k = 16;
        while (k < nlen) k = (k << 1);
        k = (k << 1);
        ibuf->name = malloc(k);
        if (name != NULL)
            memcpy(ibuf->name, name, nlen);
    } else {
        return NULL;
    }
    if (flags & IBUF_REF_DATA) {
        ibuf->data = data;
    }
    else if (flags & IBUF_COPY_DATA) {
        int k = 16;
        while (k < dlen) k = (k << 1);
        k = (k << 1);
        ibuf->data = malloc(k);
        if (data != NULL)
            memcpy(ibuf->data, data, dlen);
    } else {
        return NULL;
    }
    return ibuf;
}

struct status_info* ibuf_sinfo_init(char *name, size_t nlen, unsigned int flags)
{
    struct status_info* sbuf = (struct status_info*) malloc (sizeof(struct status_info));
    sbuf->nlen = nlen;
    if (flags & IBUF_REF_NAME) {
        sbuf->name_buf = name;
    }
    else if (flags & IBUF_COPY_NAME) {
        int k = 16;
        while (k < nlen) k = (k << 1);
        k = (k << 1);
        sbuf->name_buf = malloc(k);
        if (name != NULL)
            memcpy(sbuf->name_buf, name, nlen);
    } else {
        return NULL;
    }
    return sbuf;
}


struct touch_info* ibuf_tinfo_init(char *name, size_t nlen, unsigned int flags)
{
    struct touch_info* tbuf = (struct touch_info*) malloc (sizeof(struct touch_info));
    tbuf->__realsize = 1024;
    tbuf->nlen = nlen;
    if (flags & IBUF_REF_NAME) {
        tbuf->name = name;
    }
    else if (flags & IBUF_COPY_NAME) {
        int k = 16;
        while (k < nlen) k = (k << 1);
        k = (k << 1);
        tbuf->name = malloc(k);
        if (name != NULL)
            memcpy(tbuf->name, name, nlen);
    } else {
        return NULL;
    }
    return tbuf;
}

int ibuf_interest_reset(struct isockbuf* ibuf, size_t nlen)
{
    ibuf->nlen = nlen;
    return 0;
}

int ibuf_data_reset(struct isockbuf* ibuf, size_t nlen, size_t dlen)
{
    ibuf->nlen = nlen;
    ibuf->dlen = dlen;
    return 0;
}

int ibuf_tinfo_reset(struct touch_info* tbuf, size_t nlen, char* name)
{
    tbuf->__realsize = 1024;
    tbuf->nlen = nlen;
    if (name != NULL)
        memcpy(tbuf->name, name, nlen);
    return 0;
}

int ibuf_sinfo_reset(struct status_info* sbuf, size_t nlen)
{
    sbuf->nlen = nlen;
    memset(sbuf->name_buf, nlen, 0);
    return 0;
}

int ibuf_interest_free(struct isockbuf* ibuf, unsigned int flags)
{
    if (flags & IBUF_COPY_NAME) {
        free(ibuf->name);
    }
    free(ibuf);
    return 0;
}

int ibuf_data_free(struct isockbuf* ibuf, unsigned int flags)
{
    if (flags & IBUF_COPY_NAME) {
        free(ibuf->name);
    }
    if (flags & IBUF_COPY_DATA) {
        free(ibuf->data);
    }
    free(ibuf);
    return 0;
}

int ibuf_sinfo_free(struct status_info* sbuf, unsigned int flags)
{
    if (flags & IBUF_COPY_NAME) {
        free(sbuf->name_buf);
    }
    free(sbuf);
    return 0;
}

int ibuf_tinfo_free(struct touch_info* tbuf, unsigned int flags)
{
    if (flags & IBUF_COPY_NAME) {
        free(tbuf->name);
    }
    free(tbuf);
    return 0;
}
