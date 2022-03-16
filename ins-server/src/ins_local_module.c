
#include "ins_local_module.h"

void ins_local_module(int clientfd, char* pktbuf, int pktlen, const struct prefix_path *path)
{
#ifdef	INSSLOG_PRINT
	printf("\n[+] --> ins_local_module\n");
#endif
#ifdef	INSSLOG_SYSLOG
	syslog(LOG_INFO, "[+] --> ins_local_module\n");
#endif
	int dlen = 0, ret = 0;
	answerbuf_t dns_abuf;
	int dns_abuflen = sizeof(dns_abuf);
	ins_ans_buf ins_abuf;
	int ins_abuflen = INS_AHEADERSIZE;
	ins_qry_buf *ins_qbuf = (ins_qry_buf*)pktbuf;

#ifdef	INSSLOG_PRINT
	printf("---- query ----\n");
	printf("id: %d\n", ntohs(ins_qbuf->header.id));
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
	syslog(LOG_INFO, "rd: %d\n", ins_qbuf->header.rd);
	syslog(LOG_INFO, "aa: %d\n", ins_qbuf->header.aa);
	syslog(LOG_INFO, "mincn: %d\n", ins_qbuf->header.mincn);
	syslog(LOG_INFO, "maxcn: %d\n", ins_qbuf->header.maxcn);
	syslog(LOG_INFO, "qtype: %d\n", ins_qbuf->header.qtype);
	syslog(LOG_INFO, "qnlen: %d\n", ins_qbuf->header.qnlen);
	syslog(LOG_INFO, "name: %.*s\n", ins_qbuf->header.qnlen, ins_qbuf->buf + INS_QHEADERSIZE);
#endif

	ins_abuf.header.id = ins_qbuf->header.id;
	ins_abuf.header.ancount = 0;
	ins_abuf.header.exacn = 0;
	ins_abuf.header.exaplen = 0;
	
	char *qname = ins_qbuf->buf + INS_QHEADERSIZE;
	int exaplen, exacn;

	insprefix_check_withmaxcn(qname, ins_qbuf->header.qnlen, ins_qbuf->header.maxcn, &exacn, &exaplen);
	if (exacn < ins_qbuf->header.mincn) {
		ins_abuf.header.rcode = INS_RCODE_INVALID_INSARG;
		goto process_finish;
	}
	ins_abuf.header.exacn = ins_qbuf->header.maxcn = MIN(exacn, ins_qbuf->header.maxcn);
	ins_abuf.header.exaplen = exaplen;

	// lookup cache
	ret = ins_get_entries_fromcache(ins_qbuf, &ins_abuf, &ins_abuflen);
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
		ins_abuf.header.exaplen = (ret & 0xff);
		ins_abuf.header.exacn = ((ret >> 8) & 0x0f);
	}

	char domainname[256];
	char *domainnameptr = domainname;
	dlen = insprefix_prefix2domainname_nocheck(ins_qbuf->buf + INS_QHEADERSIZE, ins_abuf.header.exaplen, domainname, 256);

	res_state res = malloc(sizeof(*res));
	dns_init(ins_qbuf, res, path->dst);
	res->retry = 1;

	while (ins_abuf.header.exacn >= ins_qbuf->header.mincn) {
		
#ifdef	INSSLOG_PRINT
		printf("lookup domainname: %s\n", domainnameptr);
#endif
#ifdef	INSSLOG_SYSLOG
		syslog(LOG_INFO, "lookup domainname: %s\n", domainnameptr);
#endif
		dns_resolve(ins_qbuf, res, domainnameptr, &dns_abuf, &dns_abuflen);
		ret = dns_parse(&ins_abuf, ins_qbuf->buf + INS_MAXPKTSIZE, &dns_abuf, dns_abuflen);		
		if (ret != 0) break;
		memset(&dns_abuf, 0, sizeof(answerbuf_t));
		dns_abuflen = sizeof(dns_abuf);
		
		while (*domainnameptr++ != '.');
		ins_abuf.header.exacn--;
	}

	dns_close(res);
	free(res);

	if (ret < 0) {
		// decode error
		ins_abuf.header.rcode = INS_RCODE_CANT_PARSE_ANS;
		ins_abuflen = INS_AHEADERSIZE;
	} 
	else if (ret == 0) {
		// no resource record found
		ins_abuf.header.exaplen = strlen(domainnameptr) + 1;
		ins_abuf.header.rcode = INS_RCODE_RECORDNOTFOUND;
		ins_abuflen = INS_AHEADERSIZE;
	} else {
		ins_abuf.header.exaplen = strlen(domainnameptr) + 1;
		ins_abuf.header.rcode = INS_RCODE_OK;
		ins_abuflen = ret;
		ins_put_entries_tocache(ins_qbuf, &ins_abuf, ins_abuflen, get_ins_ans_ttl(&ins_abuf));
	}
	
process_finish:
	
	Write(clientfd, ins_abuf.buf, ins_abuflen);

#ifdef	INSSLOG_PRINT
	printf("---- answer ----\n");
	printf("id: %d\n", ntohs(ins_abuf.header.id));
	printf("ad: %d\n", ins_abuf.header.ad);
	printf("ra: %d\n", ins_abuf.header.ra);
	printf("exacn: %d\n", ins_abuf.header.exacn);
	printf("exaplen: %d\n", ins_abuf.header.exaplen);
	printf("ancount: %d\n", ins_abuf.header.ancount);
	printf("---- ins_local_module finished. close connection. ----\n");
#endif
#ifdef	INSSLOG_SYSLOG
	syslog(LOG_INFO, "---- answer ----\n");
	syslog(LOG_INFO, "id: %d\n", ntohs(ins_abuf.header.id));
	syslog(LOG_INFO, "ad: %d\n", ins_abuf.header.ad);
	syslog(LOG_INFO, "ra: %d\n", ins_abuf.header.ra);
	syslog(LOG_INFO, "exacn: %d\n", ins_abuf.header.exacn);
	syslog(LOG_INFO, "exaplen: %d\n", ins_abuf.header.exaplen);
	syslog(LOG_INFO, "ancount: %d\n", ins_abuf.header.ancount);
	syslog(LOG_INFO, "---- ins_local_module finished. close connection. ----\n");
#endif
	close(clientfd);

	return;
}