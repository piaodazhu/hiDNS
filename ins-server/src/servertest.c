#include "ins_msgformat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ipsock.h"

// int
// set_ins_ans_entry(unsigned char* ptr, unsigned char* bound, ins_ans_entry* entry)
// {
// 	if (ptr + 8 + entry->length > bound) {
// 		return -1;
// 	}

// 	unsigned int ttl = htonl(entry->ttl);
// 	memcpy(ptr, &ttl, 4);
// 	ptr += 4;
// 	*(ptr++) = entry->type;
// 	if (entry->length < 255) {
// 		*(ptr++) = entry->length;
// 		ptr += 2;
// 	} else {
// 		*(ptr++) = 255;
// 		unsigned short length = htons(entry->length);
// 		memcpy(ptr, &length, 2);
// 		ptr += 2;
// 	}
// 	memcpy(ptr, entry->value, entry->length);
// 	printf("ttl= %d\n", entry->ttl);
// 	return 8 + entry->length;
// }

int main()
{
	ins_qry_buf qbuf;
	ins_ans_buf abuf;

	int fd = Socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_port = htons(5553);
	Bind(fd, (struct sockaddr*)&addr, sizeof(struct sockaddr_in));
	Listen(fd, 10);

	struct sockaddr_in client_addr;
	socklen_t slen;
	int connfd = Accept(fd, (struct sockaddr*)&client_addr, &slen);
	int qlen = Read(connfd, qbuf.buf, INS_MAXPKTSIZE);
	
	printf("id: %d\n", ntohs(qbuf.header.id));
	printf("rd: %d\n", qbuf.header.rd);
	printf("aa: %d\n", qbuf.header.aa);
	printf("mincn: %d\n", qbuf.header.mincn);
	printf("maxcn: %d\n", qbuf.header.maxcn);
	printf("qtype: %d\n", qbuf.header.qtype);
	printf("qnlen: %d\n", qbuf.header.qnlen);

	if (qlen != INS_QHEADERSIZE + qbuf.header.qnlen) {
		return -1;
	}
	printf("name: %.*s\n", qbuf.header.qnlen, qbuf.buf + INS_QHEADERSIZE);

	abuf.header.id = qbuf.header.id;
	abuf.header.ra = 0;
	abuf.header.ad = 0;
	abuf.header.rcode = 7;
	abuf.header.ancount = 2;
	abuf.header.exacn = 4;
	abuf.header.exaplen = 19;

	int i, len, alen = INS_AHEADERSIZE;
	char *ptr = abuf.buf + INS_AHEADERSIZE;
	char *bound = abuf.buf + INS_MAXPKTSIZE;

	ins_ans_entry aentry[2];
	aentry[0].ttl = 86400;
	aentry[0].type = INS_T_A;
	aentry[0].length = 4;
	aentry[0].value = malloc(aentry[0].length);
	in_addr_t ip1 = inet_addr("1.2.3.4");
	memcpy(aentry[0].value, &ip1, 4);
	aentry[1].ttl = 86400;
	aentry[1].type = INS_T_A;
	aentry[1].length = 4;
	aentry[1].value = malloc(aentry[1].length);
	in_addr_t ip2 = inet_addr("5.6.7.8");
	memcpy(aentry[1].value, &ip2, 4);

	for (i = 0; i < abuf.header.ancount; i++) {
		if ((len = set_ins_ans_entry(ptr, bound, aentry + i)) > 0) {
			ptr += len;
			alen += len;
		}
		else {
			break;
		}
	}
// debug
	printf("nid: %d\n", htons(abuf.header.id));
	printf("ra: %d\n", abuf.header.ra);
	printf("ad: %d\n", abuf.header.ad);
	printf("rcode: %d\n", abuf.header.rcode);
	printf("ancount: %d\n", abuf.header.ancount);
	printf("exacn: %d\n", abuf.header.exacn);
	printf("exaplen: %d\n", abuf.header.exaplen);
	printf("exacn: %d\n", abuf.header.exacn);
// end

	int nwrite = Write(connfd, abuf.buf, alen);
	close(connfd);
	return 0;
}