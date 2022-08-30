#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include "resolvmsgfmt.h"

int
get_ins_ans_entry(unsigned char* ptr, unsigned char* bound, ins_ans_entry* entry)
{
	if (bound - ptr < 8) {
		return -1;
	}
	unsigned int ttl = *((unsigned int*)ptr);
	entry->ttl = ntohl(ttl);
	entry->type = *(ptr + 4);
	ptr += 6;

	// why did I write this? Cannot remember but keep it
	// unsigned short len = ptr[0];
	// if (ptr[0] < 255) {
	// 	entry->length = len;
	// } else {
	// 	len = *((unsigned short*)(ptr + 1));
	// 	entry->length = ntohs(len);
	// }
	// ptr += 3;
	unsigned short len = *(unsigned short*)ptr;
	entry->length = ntohs(len);
	ptr += 2;

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
	*(ptr++) = 0;
	
	// why did I write this? Cannot remember but keep it
	// if (entry->length < 255) {
	// 	*(ptr++) = entry->length;
	// 	ptr += 2;
	// } else {
	// 	*(ptr++) = 255;
	// 	unsigned short length = htons(entry->length);
	// 	memcpy(ptr, &length, 2);
	// 	ptr += 2;
	// }

	unsigned short length = htons(entry->length);
	memcpy(ptr, &length, 2);
	ptr += 2;

	// // reassemble txt string
	// if (entry->type == INS_T_TXT || entry->type == INS_T_HSIG || entry->type == INS_T_HADMIN )  {
	// 	unsigned char* dptr = ptr;
	// 	unsigned char* sptr = entry->value;
	// 	int datalen = 0, actuallen = 0;
	// 	unsigned char txtlen = 0;
	// 	printf("vallen=%d\n", entry->length);
	// 	while (datalen < entry->length) {
	// 		txtlen = sptr[0];
	// 		printf("txtlen=%d\n", txtlen);
	// 		++sptr;
	// 		memcpy(dptr, sptr, txtlen);
	// 		dptr += txtlen;
	// 		sptr += txtlen;
	// 		++datalen;
	// 		datalen += txtlen;
	// 		actuallen += txtlen;
	// 	}
	// 	entry->length = actuallen;
	// 	length = htons(entry->length);
	// 	memcpy(ptr - 2, &length, 2);
	// }
	// else
	// 	memcpy(ptr, entry->value, entry->length);
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
	unsigned int id = tv.tv_usec ^ rand();

	ins_qbuf->header.id = id;
	ins_qbuf->header.aa = 0;
	ins_qbuf->header.tc = 0;
	ins_qbuf->header.rd = 1;
	ins_qbuf->header.ra = 0;
	ins_qbuf->header.cd = 1;
	ins_qbuf->header.ad = 0;
	ins_qbuf->header.od = 0;

	ins_qbuf->header.hoplimit = 3;
	ins_qbuf->header.maxcn = 0;
	ins_qbuf->header.mincn = 0;
	ins_qbuf->header.qtype = INS_T_A;
	ins_qbuf->header.qnlen = strlen(name);
	memcpy(ins_qbuf->buf + INS_QHEADERSIZE, name, strlen(name));
	qlen = INS_QHEADERSIZE + strlen(name);
	return qlen;
}

unsigned int
get_ins_ans_ttl(const ins_ans_buf* ins_abuf)
{
	if (ins_abuf == NULL) return 0;
	if (ins_abuf->header.ancount == 0) return 0;
	const unsigned char* ptr = ins_abuf->buf + INS_AHEADERSIZE;
	unsigned int ttl = *((unsigned int*)ptr);
	return ntohl(ttl);
}

unsigned int
get_ins_entry_len(const unsigned char* entrybuf)
{
	if (entrybuf == NULL) return 0;
	unsigned short len = *(unsigned short*)(entrybuf + 6);
	return ntohs(len);
}
