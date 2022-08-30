#include "ins_ipsock.h"

int Socket(int domain, int type, int protocol)
{
	int fd = socket(domain, type, protocol);
	if(fd == -1)
		perr_exit("socket error!\n");
	return fd;
}

int Bind(int sockfd,const struct sockaddr *addr, socklen_t addrlen)
{
	int ret = bind(sockfd, addr, addrlen);
	if(ret == -1)	
		perr_exit("bind error!\n");
	return ret;
}

int Listen(int sockfd, int backlog)
{ 
	int ret = listen(sockfd, backlog);
	if(ret == -1)	
		perr_exit("listen error!\n");
	return ret;
}

int Accept(int sockfd,struct sockaddr *addr, socklen_t *addrlen)//慢速系统调用
{
	int ret;
again:
	if( (ret = accept(sockfd, addr, addrlen)) == -1)
	{
		if(errno == ECONNABORTED || errno == EINTR)
			goto again;
		else
			perr_exit("accept error!\n");
	}
	return ret;
}

int TCPstart_up(struct sockaddr_in* local, int max_connect_num)
{
	int sock = Socket(AF_INET, SOCK_STREAM, 0);
        Bind(sock,(struct sockaddr*)local, sizeof(struct sockaddr));
        Listen(sock, max_connect_num);
        return sock;
}


int Connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	int ret;
	ret = connect(sockfd,addr,addrlen);
	if(ret == -1)
		perr_exit("connect error!\n");
	return ret;
}
 
int Read(int fd, void *buf, unsigned int nbytes)
{
	int n;
again:
	if((n = read(fd, buf, nbytes)) == -1)
	{
		if(errno==EINTR)
			goto again;
		else
			perr_exit("read error!\n");
	}
	return n;
}
 
int Write(int fd, const void *buf, unsigned int nbytes)
{
	int n;
again:
	if( (n = write(fd, buf, nbytes)) == -1)
	{
		if(errno==EINTR)
			goto again;
		else
			perr_exit("write error!\n");
	}
	return n;
}