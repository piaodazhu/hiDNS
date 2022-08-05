#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main()
{
	struct sockaddr_in server;
	server.sin_family = AF_INET;
	server.sin_port = htons(1038);
	server.sin_addr.s_addr = inet_addr("127.0.0.1");
	int ipsock = socket(AF_INET,SOCK_STREAM, 0);
	if (ipsock < 0) {
		printf("[x] Cannot create IP socket\n");
		return 0;
	}
	if(connect(ipsock, (struct sockaddr*)&server, sizeof(struct sockaddr_in)) < 0) {
		close(ipsock);
		printf("[x] Cannot connect with iDomainAdmin server\n");
		return 0;
	}
	char *sendbuf = "hello";
	char rcvbuf[256];
	int ret;
	ret = write(ipsock, sendbuf, strlen(sendbuf));
	printf("write %d bytes\n", ret);
	ret = read(ipsock, rcvbuf, 256);
	printf("read %d bytes\n", ret);
	close(ipsock);
	printf("recv :: %.*s\n", ret, rcvbuf);
	return 0;
}