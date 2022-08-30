#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ins_resolv.h>


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

	in_addr_t **addrlist = ins_getaddrbyname(name, nameserver, atoi(argv[3]), atoi(argv[4]));

	if (addrlist == NULL)
	{
		printf("gettxtbyname error for host: %s: %s\n", name, hstrerror(h_errno));
		return -1;
	}
	
	in_addr_t **listptr = addrlist;
	char str[INET_ADDRSTRLEN];

	while (*listptr != NULL) {
		printf("\taddress: %s\n",
			       inet_ntoa(*(struct in_addr*)(*listptr)));
		++listptr;
	}
	
	
	return 0;
}