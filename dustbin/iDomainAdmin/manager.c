#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "globalconfig.h"
#include "command.h"
#include "ipsock.h"
int main()
{
	struct sockaddr_in server_addr;
	char buffer[64];
	
	int sockfd = Socket(AF_INET, SOCK_STREAM, 0);

	bzero(&server_addr, sizeof(struct sockaddr_in));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(LOCAL_PORT);
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	
	Connect(sockfd,(struct sockaddr*)(&server_addr),sizeof(struct sockaddr));
	
    memset(buffer, 0x11, 64);
    idns_cmdenc_8byte(buffer, IDNS_ROOT_ENTITY_ID);
	Write(sockfd, buffer, 64);
	
    char rcvbuf[256];
    int rcvlen;
    rcvlen = Read(sockfd, rcvbuf, 256);
    printf("[+] rcvlen = %d, rcode = %d\n", rcvlen, rcvbuf[0]);
	close(sockfd);
	return 0;
	
}
