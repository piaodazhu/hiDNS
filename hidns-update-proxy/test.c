#include <stdio.h>
#include <string.h>
#include "ipsock.h"
#include "../ins-resolv/lib/base64.h"
int main()
{
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_port = htons(1038);
	unsigned char buf[256];
	memset(buf, 0, 256);
	base64_encode((unsigned char*)&addr, sizeof(struct sockaddr_in), buf);
	printf("%s\n", buf);
	printf("before encode size = %d, after encode size = %d\n", sizeof(addr), strlen(buf));
	return 0;
}