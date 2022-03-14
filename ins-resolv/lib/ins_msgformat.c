#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include "ins_msgformat.h"

int
get_ins_ans_entry(unsigned char* ptr, unsigned char* bound, ins_ans_entry* entry)
{
	if (bound - ptr < 6) {
		return -1;
	}
	unsigned int ttl = *((unsigned int*)ptr);
	entry->ttl = ntohl(ttl);
	entry->type = *(ptr + 4);
	ptr += 5;
	unsigned short len = ptr[0];
	if (ptr[0] < 255) {
		entry->length = len;
	} else {
		len = *((unsigned short*)(ptr + 1));
		entry->length = ntohs(len);
	}
	ptr += 3;

	if (bound - ptr < entry->length) {
		return -2;
	}

	// do we need copy the buffer?
	entry->value = ptr;
	return 8 + entry->length;
}

int
set_ins_ans_entry(unsigned char* ptr, unsigned char* bound, ins_ans_entry* entry)
{
	if (ptr + 8 + entry->length > bound) {
		return -1;
	}

	unsigned int ttl = htonl(entry->ttl);
	memcpy(ptr, &ttl, 4);
	ptr += 4;
	*(ptr++) = entry->type;
	if (entry->length < 255) {
		*(ptr++) = entry->length;
		ptr += 2;
	} else {
		*(ptr++) = 255;
		unsigned short length = htons(entry->length);
		memcpy(ptr, &length, 2);
		ptr += 2;
	}
	memcpy(ptr, entry->value, entry->length);

	return 8 + entry->length;
}

int 
ins_init_query_buf(ins_qry_buf* ins_qbuf, unsigned char* bound, const char* name, int nlen)
{
	if (ins_qbuf->buf + nlen + INS_QHEADERSIZE > bound) return -1;
	int qlen;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	unsigned short id = tv.tv_usec % 65171;
	ins_qbuf->header.id = id;
	ins_qbuf->header.rd = 0;
	ins_qbuf->header.aa = 0;
	ins_qbuf->header.hoplimit = 3;
	ins_qbuf->header.maxcn = 0;
	ins_qbuf->header.mincn = 0;
	ins_qbuf->header.qtype = INS_T_A;
	ins_qbuf->header.qnlen = strlen(name);
	memcpy(ins_qbuf->buf + INS_QHEADERSIZE, name, strlen(name));
	qlen = INS_QHEADERSIZE + strlen(name);
	return qlen;
}