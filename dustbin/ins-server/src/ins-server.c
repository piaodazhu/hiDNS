#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "ipsock.h"
#include "loadconf.h"
#include "ins_cache.h"

// #define INS_UNIX_SOCK

#ifdef INS_UNIX_SOCK
#include <sys/un.h>
#endif

void *ins_session_process(void *arg)
{
	ins_qry_buf qbuf;
	ins_ans_buf abuf;
	int rcvlen, sndlen;

	struct session_args sargs = *((struct session_args*) arg);
	int sockfd = sargs.sockfd;
	struct sockaddr_in remote = sargs.remote;

	memcpy(qbuf.buf, sargs.buf, sargs.buflen);
	rcvlen = sargs.buflen;
	free(sargs.buf);
	free(arg);
	// rcvlen = Read(sockfd, qbuf.buf, INS_UDPMAXSIZE);
	// packet check
	if (qbuf.header.qnlen > 255 || rcvlen != qbuf.header.qnlen + INS_QHEADERSIZE) {
		// invalid packet
		abuf.header.rcode = INS_RCODE_INVALID_PACKET;
		goto error_out;
	}
	if (qbuf.header.maxcn > 8 || qbuf.header.maxcn < qbuf.header.mincn) {
		// invalid components count
		abuf.header.rcode = INS_RCODE_INVALID_CCOUNT;
		goto error_out;
	}
	if (qbuf.buf[INS_QHEADERSIZE] != '/') {
		// invalid prefix
		abuf.header.rcode = INS_RCODE_INVALID_PREFIX;
		goto error_out;
	}
	// in routed module, sockfd must be closed and answer must be sent afterprocess 
	rkt_route(&sargs, qbuf.buf + INS_QHEADERSIZE, qbuf.header.qnlen, qbuf.buf, rcvlen);
	pthread_exit(NULL);
error_out:
	abuf.header.id = qbuf.header.id;
	abuf.header.ancount = 0;
	if (sendto(sockfd, abuf.buf, INS_AHEADERSIZE, 0, (struct sockaddr*)&remote, sizeof(remote)) < 0)
        { 
                perror("sendto");
                exit(4);
        }
	
	// sndlen = Write(sockfd, abuf.buf, INS_AHEADERSIZE);
	// close(sockfd);
	pthread_exit(NULL);
}

int main(int argc, char **argv)
{
	ins_connect_cache();
	openlog("ins-server", LOG_CONS | LOG_PID, 0);
	char *configFile;
	if (argc == 1) {
		if (access("config.json", R_OK) != -1)
			configFile = "config.json";
		else if (access("../config.json", R_OK) != -1)
			configFile = "../config.json";
		else if (access("/etc/ins-server/config.json", R_OK) != -1)
			configFile = "/etc/ins-server/config.json";
		else {
#ifdef	INSSLOG_PRINT
			printf("[x] can't find config.json. exit.\n");
#endif
#ifdef	INSSLOG_SYSLOG
			syslog(LOG_ERR, "can't find config.json. exit.\n");
#endif
			exit(1);
		}

	}
	else if (argc == 3 && strlen(argv[1]) == 2 && argv[1][0] == '-' && argv[1][1] == 'c') {
		configFile = argv[2];
	}
	load_conf_json(configFile);	

	int connfd, sockfd;
#ifdef INS_UNIX_SOCK
	struct sockaddr_un unixserver;
	int ret;
	unixserver.sun_family = AF_UNIX;
	if (access("/tmp/hidns.sock", 0) == 0) {
		ret = remove("/tmp/hidns.sock");
		printf("remove file, ret = %d\n", ret);
	}
	strcpy(unixserver.sun_path, "/tmp/hidns.sock");
	listenfd = socket(AF_UNIX, SOCK_STREAM, 0);
	// printf("listenfd = %d\n", listenfd);
	ret = bind(listenfd, (struct sockaddr*) &unixserver, sizeof(struct sockaddr_un));   
	// printf("bindret = %d\n", ret);
	ret = listen(listenfd, 20);
	// printf("listenret = %d\n", ret);

#ifdef	INSSLOG_PRINT
			printf("[+] start UNIX SOCK server...\n");
#endif
#ifdef	INSSLOG_SYSLOG
			syslog(LOG_ERR, "[+] start UNIX SOCK server...\n");
#endif

#else
	// listenfd = TCPstart_up(&GLOBAL_LOCALADDR, 1000);
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(bind(sockfd, (struct sockaddr*)&GLOBAL_LOCALADDR, sizeof(GLOBAL_LOCALADDR)) < 0)
	{
		perror("bind");
		exit(2);
	}
#endif

	struct sockaddr_in remote;
	socklen_t addrlen = sizeof(struct sockaddr);

	struct session_args *sargs;
	pthread_t tid;

	unsigned char* rcvbuf;

#ifdef	INSSLOG_PRINT
			printf("[+] start UDP server...\n");
#endif
#ifdef	INSSLOG_SYSLOG
			syslog(LOG_ERR, "[+] start UDP server...\n");
#endif

	while (1)
	{
#ifdef INS_UNIX_SOCK
		connfd = accept(listenfd, (struct sockaddr*)&remote, &addrlen);
#else
		// connfd = Accept(listenfd,(struct sockaddr*)&remote, &addrlen);
		
		sargs = (struct session_args*) malloc (sizeof(struct session_args));
		rcvbuf = malloc(INS_UDPMAXSIZE);
		
		int rlen = recvfrom(sockfd, rcvbuf, INS_UDPMAXSIZE, 0, (struct sockaddr*)&remote, &addrlen);
		// printf("[+] sockfd = %d\n");
		if(rlen < 0)
		{ 
			perror("recvfrom");
			exit(3);
		}

#ifdef	INSSLOG_PRINT
			printf("accept new client from: %s: %d\n", inet_ntoa(remote.sin_addr), ntohs(remote.sin_port));
#endif
#ifdef	INSSLOG_SYSLOG
			syslog(LOG_INFO, "accept new client from: %s: %d\n", inet_ntoa(remote.sin_addr), ntohs(remote.sin_port));
#endif

#endif
		if (errno == EINTR) {
			continue;
		}
		sargs->remote = remote;
		sargs->sockfd = sockfd;
		sargs->buf = rcvbuf;
		sargs->buflen = rlen;

		pthread_create(&tid, NULL, ins_session_process, (void *)sargs);
		pthread_detach(tid);

	}
	ins_disconnect_cache();
	return 0;
}