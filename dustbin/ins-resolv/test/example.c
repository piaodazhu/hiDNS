#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ins_resolv.h>
#include "../lib/base64.h"

int main(int argc, char **argv)
{
	if (argc != 5)
	{
		printf("Usage: %s nameserverIP name mincomponentcount maxcomponentcount\n", *argv);
		printf("Use example: %s 192.168.66.68 /edu/bit/lab1/students/1234.index 2 4\n", *argv);
		return -1;
	}
	// ins_connect_cache();
	char* nameserver = argv[1];
	char *name = argv[2];

	// char **txtlist = ins_gettxtbyname(name, nameserver, atoi(argv[3]), atoi(argv[4]));

	// if (txtlist == NULL)
	// {
	// 	printf("gettxtbyname error for host: %s: %s\n", name, hstrerror(h_errno));
	// 	return -1;
	// }
	// char **listptr = txtlist;
	// while (*listptr != NULL) {
	// 	printf("%s\n", *listptr);
	// 	++listptr;
	// }
	struct sockaddr_in nserver;
	nserver.sin_family = AF_INET;
	nserver.sin_port = htons(5553);
	nserver.sin_addr.s_addr = inet_addr(nameserver);

	hidns_resolv_ans_t* ans = ins_resolv2(name, strlen(name), &nserver, atoi(argv[3]), atoi(argv[4]), INS_T_HADMIN, RESOLV_FLAG_MUST_VERIFY);

	if (ans == NULL)
	{
		printf("hidns_resolv error for host: %s: %s\n", name, hstrerror(h_errno));
		return -1;
	}
	
	unsigned char** rrset_listptr = ans->rrset_lst;
	
	unsigned short len;
	unsigned char addrbuf[256];
	unsigned short addrlen;
	struct sockaddr_in *addrptr;
	int i = 0;
	ins_ans_entry aentry;
	for (i = 0; i < ans->rrsetsize; i++) {
		// get value and print
		char* buf = ans->rrset_lst[i];
		len = *(unsigned short*)buf;
		get_ins_ans_entry(buf + 2, buf + 256, &aentry);
		printf("len=%u\n", aentry.length);
		addrlen = base64_decode(aentry.value, aentry.length, addrbuf);
		addrptr = (struct sockaddr_in*)addrbuf;
		// printf("%c %c %c\n", aentry.value[1], aentry.value[23], aentry.value[24]);
		if (sizeof(struct sockaddr_in) == addrlen) {
			printf("%s: %u\n", inet_ntoa(addrptr->sin_addr), htons(addrptr->sin_port));
		}
		
	}
	
	return 0;
}