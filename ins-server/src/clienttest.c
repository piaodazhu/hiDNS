#include "ins_msgformat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ipsock.h"

// int
// get_ins_ans_entry(unsigned char* ptr, unsigned char* bound, ins_ans_entry* entry)
// {
// 	if (bound - ptr < 6) {
// 		return -1;
// 	}
// 	unsigned int ttl = *((unsigned int*)ptr);
// 	entry->ttl = ntohl(ttl);
// 	entry->type = *(ptr + 4);
// 	ptr += 5;
// 	unsigned short len = ptr[0];
// 	if (ptr[0] < 255) {
// 		entry->length = len;
// 	} else {
// 		len = *((unsigned short*)(ptr + 1));
// 		entry->length = ntohs(len);
// 	}
// 	ptr += 3;

// 	if (bound - ptr < entry->length) {
// 		return -2;
// 	}

// 	// do we need copy the buffer?
// 	entry->value = ptr;

// 	return 8 + entry->length;
// }

int main()
{
	ins_qry_buf qbuf;
	ins_ans_buf abuf;
	char *name = "/edu/bit/lab1/news/2021/good-news.md";
	INS_QUERY_HEADER header;
	header.id = htons(1234);
	header.rd = 0;
	header.aa = 1;
	header.reserved = 0;
	header.maxcn = 4;
	header.mincn = 1;
	header.qtype = INS_T_A;
	header.qnlen = strlen(name);
	memcpy(qbuf.buf, &header, INS_QHEADERSIZE);
	memcpy(qbuf.buf + INS_QHEADERSIZE, name, strlen(name));
	int qlen = INS_QHEADERSIZE + strlen(name);
	int alen = 0;
// debug
	printf("nid: %d\n", htons(qbuf.header.id));
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
// end
	int fd = Socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(5553);
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	Connect(fd, (struct sockaddr*)&addr, sizeof(struct sockaddr_in));
	
	// send
	Write(fd, qbuf.buf, qlen);
	// receive
	alen = Read(fd, abuf.buf, INS_UDPMAXSIZE);
	close(fd);

	printf("id: %d\n", ntohs(abuf.header.id));
	printf("ra: %d\n", abuf.header.ra);
	printf("ad: %d\n", abuf.header.ad);
	printf("rcode: %d\n", abuf.header.rcode);
	printf("ancount: %d\n", abuf.header.ancount);
	printf("exacn: %d\n", abuf.header.exacn);
	printf("exaplen: %d\n", abuf.header.exaplen);


	printf("exacn: %d\n", abuf.header.exacn);
	char* ptr = (char*)&abuf + INS_AHEADERSIZE;
	char* bound = (char*)&abuf + alen;
	int i, len;
	ins_ans_entry aentry;
	for (i = 0; i < abuf.header.ancount; i++) {
		if ((len = get_ins_ans_entry(ptr, bound, &aentry)) > 0) {
			printf("entry %d: \n", i);
			printf("\tttl: %d\n", aentry.ttl);
			printf("\ttype: %d\n", aentry.type);
			printf("\tlength: %d\n", aentry.length);
			struct in_addr addr;
			addr.s_addr = *((uint32_t*)aentry.value);
			printf("\tIPv4: %s\n", inet_ntoa(addr));

			ptr += len;
		}
		else {
			break;
		}	
	}
	
}