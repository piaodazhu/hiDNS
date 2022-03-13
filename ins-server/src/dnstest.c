#include <arpa/nameser.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>

static union { HEADER hdr; unsigned char buf[PACKETSZ]; } response;
int main()
{
	res_state res = malloc(sizeof(*res));
	res_ninit(res);
	res->nscount = 1;
	struct sockaddr_in dst;
	
	dst.sin_family = AF_INET;
	dst.sin_port = htons(53);
	dst.sin_addr.s_addr = inet_addr("192.168.66.68");
	res->nsaddr_list[0] = dst;
  	
	int class = C_IN;
 	int type = T_A; // from packet
 	char answer[256];
	char* name = "www.qq.com"; 
 	int size = res_nsearch(res, name, class, type, response.buf, sizeof(response));  /* answer中为域名解析的结果 */
 	res_nclose(res);
	char* responseend = response.buf + size;
	char* responsepos = response.buf + sizeof(HEADER);

	int m = ntohs(response.hdr.qdcount);
	int n = ntohs(response.hdr.ancount);
	
	
	printf("m = %d, n = %d\n", m, n);
	return 0;
}
