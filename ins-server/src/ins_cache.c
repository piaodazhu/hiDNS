#include "ins_cache.h"
#include <stdio.h>
#include <hiredis/hiredis.h>
#include <string.h>
#include "ins_msgformat.h"
#include "ins_prefix.h"

redisContext *conn;

int
ins_connect_cache()
{
	// conn = redisConnect("127.0.0.1", 6379);
	conn = redisConnectUnix("/tmp/redis.sock");
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

	if (conn == NULL) 
		return -2; // treat as miss

	redisReply *reply;
	const char* pptr = querybuf->buf + INS_QHEADERSIZE;
	int cn = 0, plen = 0;
	if (insprefix_check_withmaxcn(pptr, querybuf->header.qnlen, querybuf->header.maxcn, &cn, &plen) < 0)
		return -1;
	
	int firstlookup = 1;
lookupcache:
	reply = redisCommand(conn, "get %d:%b", querybuf->header.qtype, pptr, plen);
	// printf("+cmd: get %d:%.*s\n", querybuf->header.qtype, plen, pptr);
	if (reply->type == REDIS_REPLY_NIL) {
		goto missed;
	}
	switch (reply->str[0]) {
		// 0 jump
		// 1 value
	// case 0: {
	// 	ansbuf->header.id = querybuf->header.id;
	// 	ansbuf->header.rcode = INS_RCODE_CACHE_NORECORD;
	// 	ansbuf->header.exaplen = 0;
	// 	ansbuf->header.ancount = 0;
	// 	*alen = INS_AHEADERSIZE;
	// 	freeReplyObject(reply);
	// 	return 0;
	// }
	case 0: {
		cn = reply->str[2];
		plen = reply->str[1];
		freeReplyObject(reply);
		if (cn < querybuf->header.mincn) {
			ansbuf->header.id = querybuf->header.id;
			ansbuf->header.rcode = INS_RCODE_CACHE_NORECORD;
			ansbuf->header.exaplen = plen;
			ansbuf->header.exacn = cn;
			ansbuf->header.ancount = 0;
			*alen = INS_AHEADERSIZE;
			return -1; // no record!
		}
				
		firstlookup = 0;
		goto lookupcache;
	}
	case 1: {
		int vlen = reply->len - 3;
		*alen = vlen;
		memcpy(ansbuf->buf, reply->str + 3, vlen);
		ansbuf->header.id = querybuf->header.id;
		freeReplyObject(reply);
		return 0; // cache hit!
	}
	default: exit(2); break;
	}
missed:
	*alen = INS_AHEADERSIZE;
	freeReplyObject(reply);
	if (firstlookup)
		return -2; // cache miss.
	else {
		int ret = 0;
		ret |= (plen & 0xff);
		ret |= ((cn & 0x0f) << 8);
		return ret; // find exact component number, but the second lookup is missed.
	}
}

int
ins_put_entries_tocache(const ins_qry_buf* querybuf, const ins_ans_buf* ansbuf, int alen, int expiretime)
{
	if (conn == NULL || expiretime < 0) return -2;
	
	unsigned char ancount = ansbuf->header.ancount;
	if (ancount == 0) 
		return -1;

	unsigned char exaplen = ansbuf->header.exaplen;
	unsigned char exacn = ansbuf->header.exacn;
	const char* pptr = querybuf->buf + INS_QHEADERSIZE;
	int cn, plen;
	unsigned char valuebuf[1024] = {0};
	unsigned char* valueptr;
	unsigned char curlen;
	redisReply *reply;

	if (insprefix_check_withmaxcn(pptr, querybuf->header.qnlen, querybuf->header.maxcn, &cn, &plen) < 0)
		return -2;
	
	for (curlen = plen; curlen > exaplen; curlen--) {
		if (pptr[curlen - 1] == '/') {
			valueptr = valuebuf;
			*valueptr++ = 0;
			*valueptr++ = exaplen;
			*valueptr++ = exacn;
			reply = redisCommand(conn, "set %d:%b %b EX %d", querybuf->header.qtype, pptr, curlen, valuebuf, 3, expiretime);
			// printf("+cmd: set %d:%.*s %.*s EX %d\n", querybuf->header.qtype, curlen, pptr, 2, valuebuf, expiretime);
			freeReplyObject(reply);
		}
	}
	valueptr = valuebuf;
	*valueptr++ = 1; 
	*valueptr++ = exaplen;
	*valueptr++ = exacn;
	memcpy(valueptr, ansbuf->buf, alen);

	reply = redisCommand(conn, "set %d:%b %b EX %d", querybuf->header.qtype, pptr, curlen, valuebuf, 3 + alen, expiretime);
	// printf("+cmd: set %d:%.*s %.*s EX %d\n", querybuf->header.qtype, curlen, pptr, 2, valuebuf, expiretime);
	freeReplyObject(reply);
	
	return 0;
}