#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "hidns_cache.h"
#include "ins_msgformat.h"
#include "ins_prefix.h"
#include "hashmap.h"

struct hashmap *pec_cache;
#ifdef INS_CACHE_LOCK
pthread_mutex_t mutex;
#endif

int user_compare(const void *a, const void *b, void *udata) {
    const pec_item *ua = a;
    const pec_item *ub = b;
//     printf("user compare\n");
    if (a == NULL || b == NULL || ua->qtype != ub->qtype || ua->pfxlen != ub->pfxlen ) return -1;
    return memcmp(ua->prefix, ub->prefix, ua->pfxlen);
}

bool user_iter(const void *item, void *udata) {
	// printf("TAG02\n");
    const pec_item *u = item;
    printf("type = %u, prefix = %.*s\n", u->qtype, u->pfxlen, u->prefix);
    return true;
}

uint64_t user_hash(const void *item, uint64_t seed0, uint64_t seed1) {
	// printf("user hash\n");
	const pec_item *u = item;
	char buf[260];
	int len = sprintf(buf, "%u:%.*s", u->qtype, u->pfxlen, u->prefix);
	// printf("%s\n", buf);
	return hashmap_murmur(buf, len, seed0, seed1);
}

void user_free(void *item) {
	const pec_item *u = item;
	if (u->prefix) free(u->prefix);
	if (u->value) free(u->value);
}

int
ins_connect_cache()
{
	// pec_cache = hashmap_new(sizeof(pec_item), 0, 0, 0, user_hash, user_compare, user_free, NULL);
	
#ifdef INS_CACHE_LOCK
	if (pthread_mutex_init(&mutex, NULL) != 0){
		printf("mutex init error. disable prefix expansion cache.\n");
                hashmap_free(pec_cache);
		return -2;
        }
#endif
	return 0;
}

int
ins_disconnect_cache()
{
#ifdef INS_CACHE_LOCK
	pthread_mutex_destroy(&mutex);
#endif
	if (pec_cache != NULL)
		hashmap_free(pec_cache);
	return 0;
}

int
ins_get_entries_fromcache(const ins_qry_buf* querybuf, ins_ans_buf* ansbuf, int* alen)
{

	if (pec_cache == NULL) 
		return -2; // treat as miss

	pec_item *item;
	char *prefix;
	const char* pptr = querybuf->buf + INS_QHEADERSIZE;
	int cn = 0, plen = 0;
	if (insprefix_check_withmaxcn(pptr, querybuf->header.qnlen, querybuf->header.maxcn, &cn, &plen) < 0)
		return -1;
	
	int firstlookup = 1;
#ifdef INS_CACHE_LOCK	
	if (pthread_mutex_lock(&mutex) != 0){
                fprintf(stdout, "lock error!\n");
        }
#endif
lookupcache:
	prefix = malloc(plen);
	memcpy(prefix, pptr, plen);
	// printf("TAG1\n");
	item = hashmap_get(pec_cache, &(pec_item) {
		.qtype = querybuf->header.qtype,
		.pfxlen = plen,
		.prefix = prefix
	});
	// printf("TAG2\n");
	free(prefix);
	if (item == NULL) {
		// printf("TAG7\n");
		goto missed;
	}
	// reply = redisCommand(conn, "get %d:%b", querybuf->header.qtype, pptr, plen);
	// // printf("+cmd: get %d:%.*s\n", querybuf->header.qtype, plen, pptr);
	// if(reply == NULL) {
	// 	printf("reply return null!\n");
	// 	redisReconnect(conn);
	// 	goto lookupcache;
	// }
	// if (reply->type == REDIS_REPLY_NIL) {	
	// 	goto missed;
	// }
	switch (item->value[0]) {
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
		cn = item->value[2];
		plen = item->value[1];
#ifdef INS_CACHE_LOCK
		pthread_mutex_unlock(&mutex);
#endif
		if (cn < querybuf->header.mincn) {
			ansbuf->header.id = querybuf->header.id;
			ansbuf->header.aa = 0;
			ansbuf->header.rcode = INS_RCODE_CACHE_NORECORD;
			ansbuf->header.exaplen = plen;
			ansbuf->header.exacn = cn;
			ansbuf->header.ancount = 0;
			*alen = INS_AHEADERSIZE;
			// printf("TAG8\n");
			return -1; // no record!
		}
				
		firstlookup = 0;
		goto lookupcache;
	}
	case 1: {
		int vlen = item->vallen - 3;
		*alen = vlen;
		ins_ans_buf* cached_answer_ptr = (ins_ans_buf*)(item->value + 3);
		// printf("len = %d, %.*s\n", item->vallen, item->vallen - INS_AHEADERSIZE, item->value + INS_AHEADERSIZE);
		// printf("%u, %u, %u, %u, %u\n", cached_answer_ptr->header.qtype, cached_answer_ptr->header.exacn, cached_answer_ptr->header.exaplen, cached_answer_ptr->header.ancount, vlen - INS_AHEADERSIZE);
		memcpy(ansbuf->buf + INS_AHEADERSIZE, cached_answer_ptr->buf + INS_AHEADERSIZE, vlen - INS_AHEADERSIZE);
		ansbuf->header.exacn = cached_answer_ptr->header.exacn;
		ansbuf->header.exaplen = cached_answer_ptr->header.exaplen;
		ansbuf->header.ancount = cached_answer_ptr->header.ancount;
#ifdef INS_CACHE_LOCK
		pthread_mutex_unlock(&mutex);
#endif
		ansbuf->header.aa = 0;
		ansbuf->header.id = querybuf->header.id;
		// printf("TAG9\n");
		return 0; // cache hit!
	}
	default: exit(2); break;
	}
missed:
	*alen = INS_AHEADERSIZE;
#ifdef INS_CACHE_LOCK
	pthread_mutex_unlock(&mutex);
#endif
	if (firstlookup) {
		// printf("TAG10\n");
		return -2; // cache miss.
	}
		
	else {
		int ret = 0;
		ret |= (plen & 0xff);
		ret |= ((cn & 0x0f) << 8);
		// printf("TAG11\n");
		return ret; // find exact component number, but the second lookup is missed.
	}
}

int
ins_put_entries_tocache(const ins_qry_buf* querybuf, const ins_ans_buf* ansbuf, int alen, int expiretime)
{
	if (pec_cache == NULL || expiretime < 0) return -2;
	// return 0;
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

	unsigned char* prefixmem;
	unsigned char* valmem;

	if (insprefix_check_withmaxcn(pptr, querybuf->header.qnlen, querybuf->header.maxcn, &cn, &plen) < 0)
		return -2;
#ifdef INS_CACHE_LOCK	
	if (pthread_mutex_lock(&mutex) != 0){
                fprintf(stdout, "lock error!\n");
        }
#endif
	for (curlen = plen; curlen > exaplen; curlen--) {
		if (pptr[curlen - 1] == '/') {
			valueptr = valuebuf;
			*valueptr++ = 0;
			*valueptr++ = exaplen;
			*valueptr++ = exacn;

			prefixmem = malloc(curlen);
			memcpy(prefixmem, pptr, curlen);
			valmem = malloc(3);
			memcpy(valmem, valuebuf, 3);
			// printf("TAG3\n");
			hashmap_delete(pec_cache, &(pec_item){
				.qtype = querybuf->header.qtype,
				.pfxlen = curlen,
				.prefix = prefixmem});
			hashmap_set(pec_cache, &(pec_item){
				.qtype = querybuf->header.qtype,
				.pfxlen = curlen,
				.vallen = 3,
				.prefix = prefixmem,
				.value = valmem});
			// printf("TAG4\n");

			// reply = redisCommand(conn, "set %d:%b %b EX %d", querybuf->header.qtype, pptr, curlen, valuebuf, 3, expiretime);
			// // printf("+cmd: set %d:%.*s %.*s EX %d\n", querybuf->header.qtype, curlen, pptr, 2, valuebuf, expiretime);
			// freeReplyObject(reply);
		}
	}
	valueptr = valuebuf;
	*valueptr++ = 1; 
	*valueptr++ = exaplen;
	*valueptr++ = exacn;
	// memcpy(valueptr, ansbuf->buf, alen);

	prefixmem = malloc(curlen);
	memcpy(prefixmem, pptr, curlen);
	valmem = malloc(3 + alen);
	memcpy(valmem, valuebuf, 3);
	memcpy(valmem + 3, ansbuf->buf, alen);
	// printf("TAG5\n");
	hashmap_delete(pec_cache, &(pec_item){
		.qtype = querybuf->header.qtype,
		.pfxlen = curlen,
		.prefix = prefixmem});
	hashmap_set(pec_cache, &(pec_item){
		.qtype = querybuf->header.qtype,
		.pfxlen = curlen,
		.vallen = 3 + alen,
		.prefix = prefixmem,
		.value = valmem});
	// printf("TAG6\n");
		
	// reply = redisCommand(conn, "set %d:%b %b EX %d", querybuf->header.qtype, pptr, curlen, valuebuf, 3 + alen, expiretime);
	// // printf("+cmd: set %d:%.*s %.*s EX %d\n", querybuf->header.qtype, curlen, pptr, 2, valuebuf, expiretime);
	// freeReplyObject(reply);
#ifdef INS_CACHE_LOCK
	pthread_mutex_unlock(&mutex);
#endif	
	return 0;
}