#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ins_resolv.h"


int main(int argc, char **argv)
{
	if (argc != 5)
	{
		printf("Usage: %s nameserverIP name mincomponentcount maxcomponentcount\n", *argv);
		printf("Use example: %s 192.168.66.68 /edu/bit/lab1/students/1234.index 2 4\n", *argv);
		return -1;
	}

	char* nameserver = argv[1];
	char *name = argv[2];
	struct hostent *hptr;

	hptr = ins_gethostbyname(name, nameserver, atoi(argv[3]), atoi(argv[4]));
	if (hptr == NULL)
	{
		printf("gethostbyname error for host: %s: %s\n", name, hstrerror(h_errno));
		return -1;
	}
	//输出主机的规范名
	printf("\tofficial: %s\n", hptr->h_name);

	//输出主机的别名
	char **pptr;
	char str[INET_ADDRSTRLEN];
	for (pptr = hptr->h_aliases; *pptr != NULL; pptr++)
	{
		printf("\talias: %s\n", *pptr);
	}

	//输出ip地址
	switch (hptr->h_addrtype)
	{
	case AF_INET:
		pptr = hptr->h_addr_list;
		for (; *pptr != NULL; pptr++)
		{
			printf("\taddress: %s\n",
			       inet_ntop(hptr->h_addrtype, hptr->h_addr, str, sizeof(str)));
		}
		break;
	default:
		printf("unknown address type\n");
		break;
	}
}