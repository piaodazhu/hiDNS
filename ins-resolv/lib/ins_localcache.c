#include "ins_localcache.h"
#include <stdio.h>
#include <hiredis/hiredis.h>
#include <string.h>
#include "ins_msgformat.h"
#include "ins_prefix.h"

redisContext *conn;

int
ins_connect_cache()
{
	conn = redisConnect("127.0.0.1", 6379);
	if (conn->err) {
		printf("localcache disabled. need redis-server.\n");
		redisFree(conn);
		conn = NULL;
		return -1;		
	}
	return 0;
}

int
ins_disconnect_cache()
{
	if (conn != NULL)
		redisFree(conn);
	return 0;
}

int
ins_get_entries_fromcache(const ins_qry_buf* querybuf, ins_ans_buf* ansbuf, int* alen)
{
	if (conn == NULL) return -2;

	redisReply *reply;
	const char* pptr = querybuf->buf + INS_QHEADERSIZE;
	int maxcn, plen;
	if (insprefix_check_withmaxcn(pptr, querybuf->header.qnlen, querybuf->header.maxcn, &maxcn, &plen) < 0) return -1;
lookupcache:	
	reply = redisCommand(conn, "get %d:%b", querybuf->header.qtype, pptr, plen);
	// printf("+cmd: get %d:%.*s\n", querybuf->header.qtype, plen, pptr);
	if (reply->type == REDIS_REPLY_NIL || reply->len < 2) {
		goto missed;
	}
	switch (reply->str[0]) {
	case 0: {
		ansbuf->header.exaplen = 0;
		ansbuf->header.ancount = 0;
		*alen = INS_AHEADERSIZE;
		freeReplyObject(reply);
		return 0;
	}
	case 1: {
		plen = reply->str[1];
		freeReplyObject(reply);
		goto lookupcache;
	}
	case 2: {
		ansbuf->header.exaplen = reply->str[1];
		ansbuf->header.ancount = reply->str[2];
		int vlen = reply->len - 3;
		*alen = INS_AHEADERSIZE + vlen;
		memcpy(ansbuf->buf + INS_AHEADERSIZE, reply->str + 3, vlen);
		freeReplyObject(reply);
		return ansbuf->header.ancount;
	}
	default: exit(2); break;
	}
missed:
	*alen = INS_AHEADERSIZE;
	freeReplyObject(reply);
	return -1;
}

int
ins_put_entries_tocache(const ins_qry_buf* querybuf, const ins_ans_buf* ansbuf, int alen, int expiretime)
{
	if (conn == NULL) return -2;

	unsigned char valuebuf[1024];
	unsigned char* valueptr;
	unsigned char curlen;
	redisReply *reply;
	
	unsigned char ancount = ansbuf->header.ancount;
	unsigned char exaplen = ansbuf->header.exaplen;
	const char* pptr = querybuf->buf + INS_QHEADERSIZE;
	int maxcn, maxplen;
	if (insprefix_check_withmaxcn(pptr, querybuf->header.qnlen, querybuf->header.maxcn, &maxcn, &maxplen) < 0) return -1;

	for (curlen = maxplen; curlen > exaplen; curlen--) {
		if (pptr[curlen - 1] == '/') {
			valueptr = valuebuf;
			*valueptr++ = ancount == 0? 0 : 1;
			*valueptr++ = ancount == 0? 0 : exaplen;
			reply = redisCommand(conn, "set %d:%b %b EX %d", querybuf->header.qtype, pptr, curlen, valuebuf, 2, expiretime);
			// printf("+cmd: set %d:%.*s %.*s EX %d\n", querybuf->header.qtype, curlen, pptr, 2, valuebuf, expiretime);
			freeReplyObject(reply);
		}
	}
	valueptr = valuebuf;
	*valueptr++ = ancount == 0? 0 : 2; 
	*valueptr++ = ancount == 0? 0 : exaplen;
	*valueptr++ = ancount;
	memcpy(valueptr, ansbuf->buf + INS_AHEADERSIZE, alen - INS_AHEADERSIZE);

	reply = redisCommand(conn, "set %d:%b %b EX %d", querybuf->header.qtype, pptr, curlen, valuebuf, 3 + alen - INS_AHEADERSIZE, expiretime);
	// printf("+cmd: set %d:%.*s %.*s EX %d\n", querybuf->header.qtype, curlen, pptr, 2, valuebuf, expiretime);
	freeReplyObject(reply);

	return 0;
}