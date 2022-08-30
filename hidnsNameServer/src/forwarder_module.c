
#include "forwarder_module.h"

void ins_remote_module(void *sargs, char* pktbuf, int pktlen, const struct prefix_path *path)
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

	hidns_sock_ctx_t *ctx = sargs;

	ins_qry_buf *ins_qbuf = (ins_qry_buf*)pktbuf;
	ins_ans_buf ins_abuf;
	int ins_abuflen = INS_AHEADERSIZE, ret;

	ins_abuf.header.id = ins_qbuf->header.id;
	ins_abuf.header.aa = 1; // authoritative answer
	ins_abuf.header.tc = 0;
	ins_abuf.header.rd = ins_qbuf->header.rd;
	ins_abuf.header.ra = 1; // TBD: from configuration
	ins_abuf.header.cd = ins_qbuf->header.cd;
	ins_abuf.header.ad = 0;
	ins_abuf.header.od = ins_qbuf->header.od;

	ins_abuf.header.hoplimit = ins_qbuf->header.hoplimit;
	ins_abuf.header.exacn = 0;
	ins_abuf.header.exaplen = 0;
	ins_abuf.header.qtype = ins_qbuf->header.qtype;
	ins_abuf.header.ancount = 0;

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
		ins_qbuf->header.maxcn = ins_qbuf->header.mincn = ((ret >> 8) & 0x0f);
	}

	if (ins_qbuf->header.hoplimit == 0) {
		ins_abuf.header.rcode = INS_RCODE_EXCEEDHOPLIMIT;
		ins_abuflen = INS_AHEADERSIZE;
		goto process_finish;
	}
	--ins_qbuf->header.hoplimit;

	// struct sockaddr_in serveraddr = path->dst;

// just send out here, open a new fd!
// find first unused ctx
	int i;
	hidns_sock_ctx_t *newctx;

	for (i = 0; i < MAX_SOCK_CTXNUM; i++) {
		newctx = &g_ctx_array[i];
		if (newctx->state != F_UNUSED) {
			continue;
		}

		newctx->fd = hidns_open_udp_socket(2, (const struct sockaddr*)&path->dst, sizeof(path->dst));
		if (newctx->fd == -1) {
			fprintf(stderr, "Error create udp socket failed\n");
			return;
		}
		break;
	}

	if (i == MAX_SOCK_CTXNUM) {
		ins_abuf.header.rcode = INS_RCODE_SERVER_TOOBUSY;
		goto process_finish;
	}
	
	newctx->state = F_CONNECTING;
	newctx->clientaddr = ctx->clientaddr;
	newctx->socklen = ctx->socklen;
	// newctx->listenfd = ctx->fd;
	newctx->ops.send = hidns_remotectx_send;
	newctx->ops.recv = hidns_remotectx_recv;
	memcpy(newctx->query_buf, pktbuf, pktlen);
	newctx->query_len = pktlen;
	memcpy(newctx->answer_buf, &ins_abuf, ins_abuflen);
	newctx->answer_len = ins_abuflen;
	timeval_t now;
	gettimeofday(&now, NULL);
	newctx->lifetime = hidns_timer_add_long(now, g_timeout*1000);
	
	hidns_remotectx_send(newctx);

	return;

process_finish:
	// send back to client

	memcpy(ctx->answer_buf, &ins_abuf, ins_abuflen);
	ctx->answer_len = ins_abuflen;
	hidns_listenctx_send(ctx);
	return;
}