
#include "ins_remote_module.h"

void ins_remote_module(int clientfd, char* pktbuf, int pktlen, const struct prefix_path *path)
{
	// forwarding the packet to another ins-server
#ifdef	INSSLOG_PRINT
	printf("\n[+] --> ins_remote_module\n");
#endif
#ifdef	INSSLOG_SYSLOG
	syslog(LOG_INFO, "[+] --> ins_remote_module\n");
#endif
	
	// TBD:
	// set a timeout in case of server failed.


	ins_qry_buf *ins_qbuf = (ins_qry_buf*)pktbuf;
	
#ifdef	INSSLOG_PRINT
	printf("---- query ----\n");
	printf("id: %d\n", ntohs(ins_qbuf->header.id));
	printf("hoplimit: %d", ins_qbuf->header.hoplimit);
	printf("rd: %d\n", ins_qbuf->header.rd);
	printf("aa: %d\n", ins_qbuf->header.aa);
	printf("mincn: %d\n", ins_qbuf->header.mincn);
	printf("maxcn: %d\n", ins_qbuf->header.maxcn);
	printf("qtype: %d\n", ins_qbuf->header.qtype);
	printf("qnlen: %d\n", ins_qbuf->header.qnlen);
	printf("name: %.*s\n", ins_qbuf->header.qnlen, ins_qbuf->buf + INS_QHEADERSIZE);
#endif
#ifdef	INSSLOG_SYSLOG
	syslog(LOG_INFO, "---- query ----\n");
	syslog(LOG_INFO, "id: %d\n", ntohs(ins_qbuf->header.id));
	syslog(LOG_INFO, "hoplimit: %d", ins_qbuf->header.hoplimit);
	syslog(LOG_INFO, "rd: %d\n", ins_qbuf->header.rd);
	syslog(LOG_INFO, "aa: %d\n", ins_qbuf->header.aa);
	syslog(LOG_INFO, "mincn: %d\n", ins_qbuf->header.mincn);
	syslog(LOG_INFO, "maxcn: %d\n", ins_qbuf->header.maxcn);
	syslog(LOG_INFO, "qtype: %d\n", ins_qbuf->header.qtype);
	syslog(LOG_INFO, "qnlen: %d\n", ins_qbuf->header.qnlen);
	syslog(LOG_INFO, "name: %.*s\n", ins_qbuf->header.qnlen, ins_qbuf->buf + INS_QHEADERSIZE);
#endif

	ins_ans_buf ins_abuf;
	int anslen, ret;
	ins_abuf.header.id = ins_qbuf->header.id;
	ins_abuf.header.ancount = 0;

	// lookup cache
	ret = ins_get_entries_fromcache(ins_qbuf, &ins_abuf, &anslen);
#ifdef	INSSLOG_PRINT
	printf("[!] cache ret %d\n", ret);
#endif
#ifdef	INSSLOG_SYSLOG
	syslog(LOG_INFO, "[!] cache ret %d\n", ret);
#endif
	switch(ret) {
	case -2: break;
	case -1: 
	case 0: goto process_finish;
	default: 
		ins_qbuf->header.maxcn = ins_qbuf->header.mincn = ((ret >> 8) & 0x0f);
	}

	if (ins_qbuf->header.hoplimit == 0) {
		ins_abuf.header.rcode = INS_RCODE_EXCEEDHOPLIMIT;
		anslen = INS_AHEADERSIZE;
		goto process_finish;
	}
	--ins_qbuf->header.hoplimit;

	struct sockaddr_in serveraddr = path->dst;
	int sockfd = Socket(AF_INET,SOCK_STREAM, 0);
	Connect(sockfd, (struct sockaddr*)&serveraddr, sizeof(struct sockaddr_in));
	Write(sockfd, pktbuf, pktlen);
	anslen = Read(sockfd, ins_abuf.buf, INS_MAXPKTSIZE);
	close(sockfd);

	if (anslen < INS_AHEADERSIZE) {
		ins_abuf.header.rcode = INS_RCODE_CANT_PARSE_ANS;
		anslen = INS_AHEADERSIZE;
	}
	if (ins_abuf.header.rcode = INS_RCODE_OK) {
		ins_put_entries_tocache(ins_qbuf, &ins_abuf, anslen, get_ins_ans_ttl(&ins_abuf));
	}
process_finish:
	
	Write(clientfd, ins_abuf.buf, anslen);

#ifdef	INSSLOG_PRINT
	printf("---- answer ----\n");
	printf("id: %d\n", ntohs(ins_abuf.header.id));
	printf("ad: %d\n", ins_abuf.header.ad);
	printf("ra: %d\n", ins_abuf.header.ra);
	printf("exacn: %d\n", ins_abuf.header.exacn);
	printf("exaplen: %d\n", ins_abuf.header.exaplen);
	printf("ancount: %d\n", ins_abuf.header.ancount);
	printf("---- ins_remote_module finished. close connection. ----\n");
#endif
#ifdef	INSSLOG_SYSLOG
	syslog(LOG_INFO, "---- answer ----\n");
	syslog(LOG_INFO, "id: %d\n", ntohs(ins_abuf.header.id));
	syslog(LOG_INFO, "ad: %d\n", ins_abuf.header.ad);
	syslog(LOG_INFO, "ra: %d\n", ins_abuf.header.ra);
	syslog(LOG_INFO, "exacn: %d\n", ins_abuf.header.exacn);
	syslog(LOG_INFO, "exaplen: %d\n", ins_abuf.header.exaplen);
	syslog(LOG_INFO, "ancount: %d\n", ins_abuf.header.ancount);
	syslog(LOG_INFO, "---- ins_remote_module finished. close connection. ----\n");
#endif

	close(clientfd);
}