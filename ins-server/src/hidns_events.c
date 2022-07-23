#include "hidns_events.h"

hidns_sock_ctx_t *g_ctx_array = NULL;
// hidns_sock_ctx_t listenctx;
int g_timeout = 3000;
// char g_debug[64] = {0};

// bindmod: 1: bindlocal, 2: bindremote, 0: no bind
int hidns_open_udp_socket(int bindmod, const struct sockaddr *addr, socklen_t len)
{
	int fd;
	int bufsize, val;

	if ((fd = socket(addr->sa_family, SOCK_DGRAM, 0)) == -1)
	{
		fprintf(stderr, "Error create udp socket\n");
		return -1;
	}

	if (bindmod == 1)
	{
		if (bind(fd, addr, len) != 0)
		{
			fprintf(stderr, "Error bind udp socket\n");
			return -1;
		}
	}
	else if (bindmod == 2)
	{
		if (connect(fd,  addr, len) != 0)
		{
			fprintf(stderr, "Error connect udp socket\n");
			return -1;
		}
	}

	bufsize = 1024 * DEFAULT_BUF_SIZE;

	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *)&bufsize,
		       sizeof(bufsize)) < 0)
	{
		fprintf(stderr, "Warning:  setsockbuf(SO_RCVBUF) failed\n");
	}

	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *)&bufsize,
		       sizeof(bufsize)) < 0)
	{
		fprintf(stderr, "Warning:  setsockbuf(SO_SNDBUF) failed\n");
	}

	val = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, val | O_NONBLOCK);

	return fd;
}

timeval_t hidns_timer_add_long(timeval_t a, long b)
{
    timeval_t ret;

    memset(&ret, 0, sizeof(timeval_t));

    ret.tv_usec = a.tv_usec + b % 1000000;
    ret.tv_sec = a.tv_sec + b / 1000000;

    if (ret.tv_usec >= 1000000) {
        ret.tv_sec++;
        ret.tv_usec -= 1000000;
    }

    return ret;
}

timeval_t hidns_timer_sub(timeval_t a, timeval_t b)
{
    timeval_t ret;

    memset(&ret, 0, sizeof(timeval_t));

    ret.tv_usec = a.tv_usec - b.tv_usec;
    ret.tv_sec = a.tv_sec - b.tv_sec;

    if (ret.tv_usec < 0) {
        ret.tv_usec += 1000000;
        ret.tv_sec--;
    }

    return ret;
}

int hidns_timer_cmp(timeval_t a, timeval_t b)
{
    if (a.tv_sec > b.tv_sec)
        return 1;
    if (a.tv_sec < b.tv_sec)
        return -1;
    if (a.tv_usec > b.tv_usec)
        return 1;
    if (a.tv_usec < b.tv_usec)
        return -1;
    return 0;
}

int hidns_listenctx_recv(void *arg)
{
	// int l = strlen(g_debug);
	// if (l < 60) {
	// 	g_debug[l] = '1';
	// }
	// else if (l == 60) {
	// 	printf("%s\n", g_debug);
	// 	g_debug[l] = 'x';
	// }

	int ret;
	hidns_sock_ctx_t *ctx = arg;

	struct sockaddr_in remote;
	socklen_t addrlen = sizeof(struct sockaddr);

	ret = recvfrom(ctx->fd, ctx->query_buf, INS_BUFMAXSIZE, 0, (struct sockaddr *)&remote, &addrlen);
	if (ret < 0)
	{
		printf("something wrong in hidns_listenctx_recv()!");
		if (errno != EWOULDBLOCK && errno != EAGAIN)
		{
			return 0;
		}

		if (hidns_eventsys_set_fd(ctx->fd, MOD_RD, ctx->listenctx) == -1)
		{
			return 0;
		}
	}
	ctx->query_len = ret;
	// record the client address
	memcpy(&ctx->clientaddr, &remote, addrlen);
	ctx->socklen = addrlen;

	// check the packet
	ins_qry_buf *qbuf = (ins_qry_buf*)ctx->query_buf;
	ins_ans_buf *abuf = (ins_ans_buf*)ctx->answer_buf;
	// memcpy(qbuf.buf, ctx->query_buf, ret);
	if (qbuf->header.qnlen > 255 || ret != qbuf->header.qnlen + INS_QHEADERSIZE)
	{
		// invalid packet
#ifdef	INSSLOG_PRINT
		printf("invalid packet!\n");
#endif
#ifdef	INSSLOG_SYSLOG
		syslog(LOG_INFO, "invalid packet!\n");
#endif
		abuf->header.rcode = INS_RCODE_INVALID_PACKET;
		goto error_out;
	}
	if (qbuf->header.maxcn > 8 || qbuf->header.maxcn < qbuf->header.mincn)
	{
		// invalid components count
#ifdef	INSSLOG_PRINT
		printf("invalid component count!\n");
#endif
#ifdef	INSSLOG_SYSLOG
		syslog(LOG_INFO, "invalid component count!\n");
#endif
		abuf->header.rcode = INS_RCODE_INVALID_CCOUNT;
		goto error_out;
	}
	if (qbuf->buf[INS_QHEADERSIZE] != '/')
	{
		// invalid prefix
#ifdef	INSSLOG_PRINT
		printf("invalid prefix!\n");
#endif
#ifdef	INSSLOG_SYSLOG
		syslog(LOG_INFO, "invalid prefix!\n");
#endif
		abuf->header.rcode = INS_RCODE_INVALID_PREFIX;
		goto error_out;
	}
	if (qbuf->header.qtype == INS_T_HSIG)
	{
		// invalid qtype
#ifdef	INSSLOG_PRINT
		printf("invalid RR type!\n");
#endif
#ifdef	INSSLOG_SYSLOG
		syslog(LOG_INFO, "invalid RR type!\n");
#endif
		abuf->header.rcode = INS_RCODE_INVALID_RRTYPE;
		goto error_out;
	}
	// printf("tag1\n");
#ifdef	INSSLOG_PRINT
	char logbuf[256];
	int logptr = 0;
	logptr += sprintf(logbuf + logptr, "---- query ----\n");
	logptr += sprintf(logbuf + logptr, "id = %u\n", ntohl(qbuf->header.id));
	logptr += sprintf(logbuf + logptr, "aa = %d, ", qbuf->header.aa);
	logptr += sprintf(logbuf + logptr, "tc = %d, ", qbuf->header.tc);
	logptr += sprintf(logbuf + logptr, "rd = %d, ", qbuf->header.rd);
	logptr += sprintf(logbuf + logptr, "ra = %d\n", qbuf->header.ra);
	logptr += sprintf(logbuf + logptr, "cd = %d, ", qbuf->header.cd);
	logptr += sprintf(logbuf + logptr, "ad = %d, ", qbuf->header.ad);
	logptr += sprintf(logbuf + logptr, "od = %d\n", qbuf->header.od);
	logptr += sprintf(logbuf + logptr, "hoplimit = %d, ", qbuf->header.hoplimit);
	logptr += sprintf(logbuf + logptr, "mincn = %d, ", qbuf->header.mincn);
	logptr += sprintf(logbuf + logptr, "maxcn = %d\n", qbuf->header.maxcn);

	logptr += sprintf(logbuf + logptr, "qtype = %d, ", qbuf->header.qtype);
	logptr += sprintf(logbuf + logptr, "qnlen = %d\n", qbuf->header.qnlen);
	logptr += sprintf(logbuf + logptr, "name: %.*s\n", qbuf->header.qnlen, qbuf->buf + INS_QHEADERSIZE);
	printf("%.*s", logptr, logbuf);
#endif
#ifdef	INSSLOG_SYSLOG
	char logbuf[256];
	int logptr = 0;
	logptr += sprintf(logbuf + logptr, "---- query ----\n");
	logptr += sprintf(logbuf + logptr, "id = %u\n", ntohl(qbuf->header.id));
	logptr += sprintf(logbuf + logptr, "aa = %d, ", qbuf->header.aa);
	logptr += sprintf(logbuf + logptr, "tc = %d, ", qbuf->header.tc);
	logptr += sprintf(logbuf + logptr, "rd = %d, ", qbuf->header.rd);
	logptr += sprintf(logbuf + logptr, "ra = %d\n", qbuf->header.ra);
	logptr += sprintf(logbuf + logptr, "cd = %d, ", qbuf->header.cd);
	logptr += sprintf(logbuf + logptr, "ad = %d, ", qbuf->header.ad);
	logptr += sprintf(logbuf + logptr, "od = %d\n", qbuf->header.od);
	logptr += sprintf(logbuf + logptr, "hoplimit = %d, ", qbuf->header.hoplimit);
	logptr += sprintf(logbuf + logptr, "mincn = %d, ", qbuf->header.mincn);
	logptr += sprintf(logbuf + logptr, "maxcn = %d\n", qbuf->header.maxcn);

	logptr += sprintf(logbuf + logptr, "qtype = %d, ", qbuf->header.qtype);
	logptr += sprintf(logbuf + logptr, "qnlen = %d\n", qbuf->header.qnlen);
	logptr += sprintf(logbuf + logptr, "name: %.*s\n", qbuf->header.qnlen, qbuf->buf + INS_QHEADERSIZE);
	syslog(LOG_INFO, "%.*s", logptr, logbuf);
#endif

	// find path
	// send the query out
	rkt_route(ctx, qbuf->buf + INS_QHEADERSIZE, qbuf->header.qnlen, qbuf->buf, ret);
	
	if (hidns_eventsys_set_fd(ctx->fd, MOD_RD, ctx->listenctx) == -1)
	{
		fprintf(stderr, "Error set read fd:%d\n", ctx->fd);
		goto error_out;
	}
	ctx->state = F_READING;
	return 0;
error_out:
	abuf->header.id = qbuf->header.id;
	abuf->header.ancount = 0;
	// send answer back
	// memcpy(ctx->answer_buf, abuf.buf, INS_AHEADERSIZE);
	ctx->answer_len = INS_AHEADERSIZE;

	if (hidns_listenctx_send(ctx) == -1)
	{
		printf("error in send back\n");
	}
	// if (sendto(sockfd, abuf.buf, INS_AHEADERSIZE, 0, (struct sockaddr*)&remote, sizeof(remote)) < 0)
	// {
	//         perror("sendto");
	//         exit(4);
	// }
	return 0;
}

int hidns_listenctx_send(void *arg)
{
	// int l = strlen(g_debug);
	// if (l < 60) {
	// 	g_debug[l] = '2';
	// }
	// else if (l == 60) {
	// 	printf("%s\n", g_debug);
	// 	g_debug[l] = 'x';
	// }
	

	int ret;
	hidns_sock_ctx_t *ctx = arg;

	ins_ans_buf *abuf = (ins_ans_buf*)ctx->answer_buf;
	
#ifdef INSSLOG_PRINT
	char logbuf[256];
	int logptr = 0;
	logptr += sprintf(logbuf + logptr, "---- answer ----\n");
	logptr += sprintf(logbuf + logptr, "id = %u\n", ntohl(abuf->header.id));
	logptr += sprintf(logbuf + logptr, "aa = %d, ", abuf->header.aa);
	logptr += sprintf(logbuf + logptr, "tc = %d, ", abuf->header.tc);
	logptr += sprintf(logbuf + logptr, "rd = %d, ", abuf->header.rd);
	logptr += sprintf(logbuf + logptr, "ra = %d\n", abuf->header.ra);
	logptr += sprintf(logbuf + logptr, "cd = %d, ", abuf->header.cd);
	logptr += sprintf(logbuf + logptr, "ad = %d, ", abuf->header.ad);
	logptr += sprintf(logbuf + logptr, "od = %d\n", abuf->header.od);
	logptr += sprintf(logbuf + logptr, "hoplimit = %d, ", abuf->header.hoplimit);
	logptr += sprintf(logbuf + logptr, "rcode = %d\n", abuf->header.rcode);
	logptr += sprintf(logbuf + logptr, "exacn = %d, ", abuf->header.exacn);
	logptr += sprintf(logbuf + logptr, "exaplen = %d\n", abuf->header.exaplen);
	logptr += sprintf(logbuf + logptr, "qtype = %d, ", abuf->header.qtype);
	logptr += sprintf(logbuf + logptr, "ancount = %d\n", abuf->header.ancount);
	logptr += sprintf(logbuf + logptr, "name: %.*s\n", abuf->header.exaplen, abuf->buf + INS_AHEADERSIZE);

	printf("%.*s", logptr, logbuf);
#endif
#ifdef INSSLOG_SYSLOG
	char logbuf[256];
	int logptr = 0;
	logptr += sprintf(logbuf + logptr, "---- answer ----\n");
	logptr += sprintf(logbuf + logptr, "id = %u\n", ntohl(abuf->header.id));
	logptr += sprintf(logbuf + logptr, "aa = %d, ", abuf->header.aa);
	logptr += sprintf(logbuf + logptr, "tc = %d, ", abuf->header.tc);
	logptr += sprintf(logbuf + logptr, "rd = %d, ", abuf->header.rd);
	logptr += sprintf(logbuf + logptr, "ra = %d\n", abuf->header.ra);
	logptr += sprintf(logbuf + logptr, "cd = %d, ", abuf->header.cd);
	logptr += sprintf(logbuf + logptr, "ad = %d, ", abuf->header.ad);
	logptr += sprintf(logbuf + logptr, "od = %d\n", abuf->header.od);
	logptr += sprintf(logbuf + logptr, "hoplimit = %d, ", abuf->header.hoplimit);
	logptr += sprintf(logbuf + logptr, "rcode = %d\n", abuf->header.rcode);
	logptr += sprintf(logbuf + logptr, "exacn = %d, ", abuf->header.exacn);
	logptr += sprintf(logbuf + logptr, "exaplen = %d\n", abuf->header.exaplen);
	logptr += sprintf(logbuf + logptr, "qtype = %d, ", abuf->header.qtype);
	logptr += sprintf(logbuf + logptr, "ancount = %d\n", abuf->header.ancount);
	logptr += sprintf(logbuf + logptr, "name: %.*s\n", abuf->header.exaplen, abuf->buf + INS_AHEADERSIZE);

	syslog(LOG_INFO, "%.*s", logptr, logbuf);
#endif
// printf("listenctx: answer_len=%d\n", listenctx.answer_len);
	ret = sendto(ctx->fd, ctx->answer_buf, ctx->answer_len, 0, &ctx->clientaddr, ctx->socklen);
// printf("ret = %d, answerlen = %d\n", ret, ctx->answer_len);
	if (ret < 0)
	{
		if (errno != EWOULDBLOCK && errno != EAGAIN)
		{
			goto error_out;
		}

		ctx->state = F_SENDING;
		if (hidns_eventsys_set_fd(ctx->fd, MOD_WR, ctx->listenctx) == -1)
		{
			fprintf(stderr, "Error set write fd:%d\n", ctx->fd);
			goto error_out;
		}
	}
	else
	{ /* already send */
		if (ret != ctx->answer_len)
		{
			ctx->state = F_SENDING;
			// ctx->send_pos += ret;
			// if (dns_perf_eventsys_set_fd(q->fd, MOD_WR, q) == -1)
			// {
			// 	fprintf(stderr, "Error set write fd:%d\n", q->fd);
			// 	goto error_out;
			// }
			printf("send but not complete!\n");
			goto error_out;
		}

		ctx->state = F_READING;
		if (hidns_eventsys_set_fd(ctx->fd, MOD_RD, ctx->listenctx) == -1)
		{
			fprintf(stderr, "Error set read fd:%d\n", ctx->fd);
			goto error_out;
		}
	}
	ctx->state = F_READING;
	return 0;
error_out:
	return -1;
}

int hidns_localctx_recv(void *arg)
{
	// int l = strlen(g_debug);
	// if (l < 60) {
	// 	g_debug[l] = '3';
	// }
	// else if (l == 60) {
	// 	printf("%s\n", g_debug);
	// 	g_debug[l] = 'x';
	// }
	

	int ret;
	hidns_sock_ctx_t *ctx = arg;
	answerbuf_t dnsbuf;
	ins_ans_buf *abuf = (ins_ans_buf*)ctx->answer_buf;
	ins_qry_buf *qbuf = (ins_qry_buf*)ctx->query_buf;

	ret = recv(ctx->fd, dnsbuf.buf, INS_BUFMAXSIZE, 0);
	if (ret < 0)
	{
		if (errno != EWOULDBLOCK && errno != EAGAIN)
		{
			close(ctx->fd);
			ctx->state = F_UNUSED;
			return 0;
		}

		if (hidns_eventsys_set_fd(ctx->fd, MOD_RD, ctx) == -1)
		{
			close(ctx->fd);
			ctx->state = F_UNUSED;
			return 0;
		}
		return 0;
	}
	// printf("dns_parsebefore: ret = %d\n", ret);
	if (ret <= INS_UDPMAXSIZE) {
		// printf("dns_parsebefore: ret = %d\n", ret);
		ret = dns_parse((ins_ans_buf*)ctx->answer_buf, ctx->answer_buf + INS_UDPMAXSIZE, &dnsbuf, ret);
		// printf("dns_parseafter: ret = %d\n", ret);
		if (ret == 0) {
			// not found !! next level or return
			if (ctx->dname_cnum > qbuf->header.mincn) {
				// next level
				while (ctx->dname_buf[ctx->dname_ptr++] != '.');
				ctx->dname_cnum--;
				abuf->header.exaplen = strlen(ctx->dname_buf+ctx->dname_ptr) + 1;
				hidns_localctx_send(ctx);
				return 0;
			}
			// not found
			abuf->header.exaplen = strlen(ctx->dname_buf+ctx->dname_ptr) + 1;
			abuf->header.exacn = ctx->dname_cnum;
			abuf->header.rcode = INS_RCODE_RECORDNOTFOUND;
			ctx->answer_len = INS_AHEADERSIZE;

		} else if (ret < 0) {
			// decode error
			abuf->header.rcode = INS_RCODE_CANT_PARSE_ANS;
			ctx->answer_len = INS_AHEADERSIZE;
		} else {
			abuf->header.exaplen = strlen(ctx->dname_buf+ctx->dname_ptr) + 1;
			memcpy(abuf->buf + INS_AHEADERSIZE, qbuf->buf + INS_QHEADERSIZE, abuf->header.exaplen);
			abuf->header.exacn = ctx->dname_cnum;
			abuf->header.rcode = INS_RCODE_OK;
			ctx->answer_len = ret;
			if (qbuf->header.qtype != INS_T_CERT && qbuf->header.qtype != INS_T_HSIG && qbuf->header.qtype != INS_T_RRSIG) {
			// for these record type, try to fetch the signature.
				ctx->ops.send = fetch_signature;
				ctx->ops.recv = receive_signature;
				fetch_signature(ctx);
				return 0;
			}
			printf("explen=%d, answerlen=%d\n", abuf->header.exaplen, ctx->answer_len);
			ins_put_entries_tocache(qbuf, abuf, ret, get_ins_ans_ttl(abuf));
		}
	} else { // too long to put into a UDP datagram
		abuf->header.tc = 1;
		abuf->header.exaplen = strlen(ctx->dname_buf+ctx->dname_ptr) + 1;
		abuf->header.exacn = ctx->dname_cnum;
		abuf->header.rcode = INS_RCODE_CANT_PARSE_ANS;
		ctx->answer_len = INS_AHEADERSIZE;
	}
	// close fd and send the answer back
	close(ctx->fd);
	ctx->state = F_UNUSED;

	hidns_sock_ctx_t listenctx;
	listenctx.listenctx = ctx->listenctx;
	listenctx.fd = ctx->listenctx->fd;
	listenctx.state = F_PROXY;
	listenctx.clientaddr = ctx->clientaddr;
	listenctx.socklen = ctx->socklen;
	memcpy(listenctx.answer_buf, ctx->answer_buf, ctx->answer_len);
	listenctx.answer_len = ctx->answer_len;
	// printf("listenctx: answer_len=%d", listenctx.answer_len);
	hidns_listenctx_send(&listenctx);
	return 0;
}

int hidns_localctx_send(void *arg)
{
	// int l = strlen(g_debug);
	// if (l < 60) {
	// 	g_debug[l] = '4';
	// }
	// else if (l == 60) {
	// 	printf("%s\n", g_debug);
	// 	g_debug[l] = 'x';
	// }
	

	int ret;
	hidns_sock_ctx_t *ctx = arg;
	ins_qry_buf *qbuf = (ins_qry_buf*)ctx->query_buf;

#ifdef INSSLOG_PRINT
		printf("lookup domainname: %s\n", ctx->dname_buf + ctx->dname_ptr);
#endif
#ifdef INSSLOG_SYSLOG
		syslog(LOG_INFO, "lookup domainname: %s\n", ctx->dname_buf + ctx->dname_ptr);
#endif

	int len;
	unsigned char type;
	u_int8_t dnbuf[INS_PFXMAXSIZE];
	u_int8_t dnsbuf[INS_UDPMAXSIZE];
	if (qbuf->header.qtype == INS_T_HADMIN) {
		snprintf(dnbuf, INS_PFXMAXSIZE, "_hadmin.%s", ctx->dname_buf + ctx->dname_ptr);
		type = INS_T_TXT;
	}
	else {
		snprintf(dnbuf, INS_PFXMAXSIZE, "_hadmin.%s", ctx->dname_buf + ctx->dname_ptr);
		type = qbuf->header.qtype;
	}
	len = res_mkquery(QUERY, dnbuf, C_IN, type, NULL, 0, NULL, dnsbuf, INS_UDPMAXSIZE);
	if (len == -1)
	{
		fprintf(stderr, "Failed to create query packet: %s %d\n", ctx->dname_buf + ctx->dname_ptr, qbuf->header.qtype);
		return -1;
	}
	
	// HACK for longtxt. We add a OPT record to set max UDP response size 4096. 
	// If not do this, the server won't response the RR longer than 512...
	if (qbuf->header.qtype == INS_T_TXT) {
		HEADER *h = (HEADER*)dnsbuf;
		h->arcount = htons(1);
		memset(dnsbuf + len, 0, 11);
		*(dnsbuf + len + 2) = T_OPT;
		*(dnsbuf + len + 3) = 0x10;
		len += 11;
	}

	ret = send(ctx->fd, dnsbuf, len, 0);
	if (ret < 0)
	{
		if (errno != EWOULDBLOCK && errno != EAGAIN)
		{
			goto error_out;
		}

		ctx->state = F_SENDING;
		if (hidns_eventsys_set_fd(ctx->fd, MOD_WR, ctx) == -1)
		{
			fprintf(stderr, "Error set write fd:%d\n", ctx->fd);
			goto error_out;
		}
	}
	else
	{ /* already send */
		if (ret != len)
		{
			ctx->state = F_SENDING;
			// ctx->send_pos += ret;
			// if (dns_perf_eventsys_set_fd(q->fd, MOD_WR, q) == -1)
			// {
			// 	fprintf(stderr, "Error set write fd:%d\n", q->fd);
			// 	goto error_out;
			// }
			printf("send but not complete!\n");
			goto error_out;
		}
		ctx->state = F_READING;
		if (hidns_eventsys_set_fd(ctx->fd, MOD_RD, ctx) == -1)
		{
			fprintf(stderr, "Error set read fd:%d\n", ctx->fd);
			goto error_out;
		}
	}
	return 0;
error_out:
	close(ctx->fd); // may not close !!
	ctx->state = F_UNUSED;
	return -1;
}

int hidns_remotectx_recv(void *arg)
{
	// int l = strlen(g_debug);
	// if (l < 60) {
	// 	g_debug[l] = '5';
	// }
	// else if (l == 60) {
	// 	printf("%s\n", g_debug);
	// 	g_debug[l] = 'x';
	// }
	

	int ret;
	hidns_sock_ctx_t *ctx = arg;

	ret = recv(ctx->fd, ctx->answer_buf, INS_UDPMAXSIZE, 0);
	if (ret < 0)
	{
		if (errno != EWOULDBLOCK && errno != EAGAIN)
		{
			close(ctx->fd);
			ctx->state = F_UNUSED;
			return 0;
		}

		if (hidns_eventsys_set_fd(ctx->fd, MOD_RD, ctx) == -1)
		{
			close(ctx->fd);
			ctx->state = F_UNUSED;
			return 0;
		}
		return 0;
	}
	
	close(ctx->fd);
	ctx->state = F_UNUSED;
	ins_ans_buf *ins_abuf = (ins_ans_buf*)ctx->answer_buf;
	int anslen = ret;

	if (anslen < INS_AHEADERSIZE) {
		ins_abuf->header.rcode = INS_RCODE_CANT_PARSE_ANS;
		anslen = INS_AHEADERSIZE;
	}
	if (ins_abuf->header.rcode == INS_RCODE_OK) {
		ins_put_entries_tocache((ins_qry_buf*)ctx->query_buf, ins_abuf, anslen, get_ins_ans_ttl(ins_abuf));
	}

	hidns_sock_ctx_t listenctx;
	listenctx.listenctx = ctx->listenctx;
	listenctx.fd = ctx->listenctx->fd;
	listenctx.state = F_PROXY;
	listenctx.clientaddr = ctx->clientaddr;
	listenctx.socklen = ctx->socklen;
	memcpy(listenctx.answer_buf, ins_abuf, anslen);
	listenctx.answer_len = anslen;
	hidns_listenctx_send(&listenctx);
	return 0;
}

int hidns_remotectx_send(void *arg)
{
	// int l = strlen(g_debug);
	// if (l < 60) {
	// 	g_debug[l] = '6';
	// }
	// else if (l == 60) {
	// 	printf("%s\n", g_debug);
	// 	g_debug[l] = 'x';
	// }
	
	int ret;
	hidns_sock_ctx_t *ctx = arg;
	ret = send(ctx->fd, ctx->query_buf, ctx->query_len, 0);
	if (ret < 0)
	{
		if (errno != EWOULDBLOCK && errno != EAGAIN)
		{
			goto error_out;
		}

		ctx->state = F_SENDING;
		if (hidns_eventsys_set_fd(ctx->fd, MOD_WR, ctx) == -1)
		{
			fprintf(stderr, "Error set write fd:%d\n", ctx->fd);
			goto error_out;
		}
	}
	else
	{ /* already send */
		if (ret != ctx->query_len)
		{
			ctx->state = F_SENDING;
			// ctx->send_pos += ret;
			// if (dns_perf_eventsys_set_fd(q->fd, MOD_WR, q) == -1)
			// {
			// 	fprintf(stderr, "Error set write fd:%d\n", q->fd);
			// 	goto error_out;
			// }
			printf("send but not complete!\n");
			goto error_out;
		}

		ctx->state = F_READING;
		if (hidns_eventsys_set_fd(ctx->fd, MOD_RD, ctx) == -1)
		{
			fprintf(stderr, "Error set read fd:%d\n", ctx->fd);
			goto error_out;
		}
	}

	return 0;

error_out:
	close(ctx->fd);
	ctx->state = F_UNUSED;
	return -1;
}

int fetch_signature(void *arg)
{
	int ret;
	hidns_sock_ctx_t *ctx = arg;
	ins_qry_buf *qbuf = (ins_qry_buf*)ctx->query_buf;
	ins_ans_buf *abuf = (ins_ans_buf*)ctx->answer_buf;
	char signame[INS_PFXMAXSIZE];
	int sigtaglen = sprintf(signame, "_hsig_%d.", qbuf->header.qtype);
	int dnamelen = strlen(ctx->dname_buf + ctx->dname_ptr);
	if (sigtaglen + dnamelen + 1 > INS_PFXMAXSIZE) {
		// error occurs.
		goto error_out;
	}
	memcpy(signame + sigtaglen, ctx->dname_buf + ctx->dname_ptr, dnamelen + 1); // +1 means copy the '\0' as ending
#ifdef INSSLOG_PRINT
		printf("lookup domainname: %s\n", signame);
#endif
#ifdef INSSLOG_SYSLOG
		syslog(LOG_INFO, "lookup domainname: %s\n", signame);
#endif

	int len;
	u_int8_t dnsbuf[INS_UDPMAXSIZE];
	len = res_mkquery(QUERY,signame, C_IN, T_TXT, NULL, 0, NULL, dnsbuf, INS_UDPMAXSIZE);
	if (len == -1)
	{
		fprintf(stderr, "Failed to create query packet: %s TXT\n", signame);
		return -1;
	}
	ret = send(ctx->fd, dnsbuf, len, 0);
	if (ret < 0)
	{
		if (errno != EWOULDBLOCK && errno != EAGAIN)
		{
			goto error_out;
		}

		ctx->state = F_SENDING;
		if (hidns_eventsys_set_fd(ctx->fd, MOD_WR, ctx) == -1)
		{
			fprintf(stderr, "Error set write fd:%d\n", ctx->fd);
			goto error_out;
		}
	}
	else
	{ /* already send */
		if (ret != len)
		{
			ctx->state = F_SENDING;
			printf("send but not complete!\n");
			goto error_out;
		}

		ctx->state = F_READING;
		if (hidns_eventsys_set_fd(ctx->fd, MOD_RD, ctx) == -1)
		{
			fprintf(stderr, "Error set read fd:%d\n", ctx->fd);
			goto error_out;
		}
	}

	return 0;

error_out:
	close(ctx->fd); // may not close !!
	ctx->state = F_UNUSED;

	ins_put_entries_tocache(qbuf, abuf, ret, get_ins_ans_ttl(abuf));
	hidns_sock_ctx_t listenctx;
	listenctx.listenctx = ctx->listenctx;
	listenctx.fd = ctx->listenctx->fd;
	listenctx.state = F_PROXY;
	listenctx.clientaddr = ctx->clientaddr;
	listenctx.socklen = ctx->socklen;
	memcpy(listenctx.answer_buf, ctx->answer_buf, ctx->answer_len);
	listenctx.answer_len = ctx->answer_len;
	// printf("listenctx: answer_len=%d", listenctx.answer_len);
	hidns_listenctx_send(&listenctx);
	return -1;
}

int receive_signature(void *arg)
{
	int ret;
	hidns_sock_ctx_t *ctx = arg;
	answerbuf_t dnsbuf;
	ins_ans_buf sig_pseudo_buf;
	sig_pseudo_buf.header.exaplen = 0;
	ins_ans_entry sigentry;

	ins_ans_buf *abuf = (ins_ans_buf*)ctx->answer_buf;
	ins_qry_buf *qbuf = (ins_qry_buf*)ctx->query_buf;

	ret = recv(ctx->fd, dnsbuf.buf, INS_BUFMAXSIZE, 0);
	if (ret < 0)
	{
		if (errno != EWOULDBLOCK && errno != EAGAIN)
		{
			close(ctx->fd);
			ctx->state = F_UNUSED;
			return 0;
		}

		if (hidns_eventsys_set_fd(ctx->fd, MOD_RD, ctx) == -1)
		{
			close(ctx->fd);
			ctx->state = F_UNUSED;
			return 0;
		}
		return 0;
	}
	// printf("[TAG1]\n");
	// printf("dns_parsebefore: ret = %d\n", ret);
	if (ret <= INS_UDPMAXSIZE) {
		// printf("dns_parsebefore: ret = %d\n", ret);
		ret = dns_parse(&sig_pseudo_buf, sig_pseudo_buf.buf + INS_UDPMAXSIZE, &dnsbuf, ret);
		// printf("dns_parseafter: ret = %d\n", ret);
		if (ret > 0) {
			// unsigned short entrylen = get_ins_entry_len(sig_pseudo_buf.buf + INS_AHEADERSIZE) + INS_ENTRYFIXLEN;
			
			unsigned short entrylen = get_ins_ans_entry(sig_pseudo_buf.buf + INS_AHEADERSIZE, sig_pseudo_buf.buf + INS_UDPMAXSIZE, &sigentry);
			if (entrylen + ctx->answer_len <= INS_UDPMAXSIZE) {
				// obtain the signature RR
				abuf->header.ancount++;
				sigentry.type = INS_T_HSIG;
				ctx->answer_len += set_ins_ans_entry(abuf->buf + ctx->answer_len, abuf->buf + INS_UDPMAXSIZE, &sigentry);
				ins_put_entries_tocache(qbuf, abuf, ctx->answer_len, get_ins_ans_ttl(abuf));
			}
		}
		else if (ret < 0) {
			printf("[ERROR] cannot obtain signature RR.\n");
		}
	}
	// close fd and send the answer back
	close(ctx->fd);
	ctx->state = F_UNUSED;

	hidns_sock_ctx_t listenctx;
	listenctx.listenctx = ctx->listenctx;
	listenctx.fd = ctx->listenctx->fd;
	listenctx.state = F_PROXY;
	listenctx.clientaddr = ctx->clientaddr;
	listenctx.socklen = ctx->socklen;
	memcpy(listenctx.answer_buf, ctx->answer_buf, ctx->answer_len);
	listenctx.answer_len = ctx->answer_len;
	// printf("listenctx: answer_len=%d", listenctx.answer_len);
	hidns_listenctx_send(&listenctx);
	return 0;
}