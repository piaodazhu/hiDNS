#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "hidns_cache.h"
#include "ins_msgformat.h"
#include "ins_prefix.h"
#include "ttlmap.h"

ttlmap *pec_cache;

int user_compare(const void *a, const void *b, void *udata) {
    const pec_item *ua = a;
    const pec_item *ub = b;
    if (a == NULL || b == NULL || ua->qtype != ub->qtype || ua->pfxlen != ub->pfxlen ) return -1;
    return memcmp(ua->prefix, ub->prefix, ua->pfxlen);
}

bool user_iter(const void *item, void *udata) {
    const pec_item *u = item;
    printf("type = %u, prefix = %.*s\n", u->qtype, u->pfxlen, u->prefix);
    return true;
}

uint64_t user_hash(const void *item, uint64_t seed0, uint64_t seed1) {
	const pec_item *u = item;
	char buf[260];
	int len = sprintf(buf, "%u:%.*s", u->qtype, u->pfxlen, u->prefix);
	return ttlmap_murmur(buf, len, seed0, seed1);
}

void user_free(void *item) {
	const pec_item *u = item;
	if (u->prefix) free(u->prefix);
	if (u->value) free(u->value);
}

int
ins_connect_cache()
{
	pec_cache = ttlmap_new(sizeof(pec_item), 0, 0, 0, user_hash, user_compare, user_free, NULL, NULL);
	return 0;
}

int
ins_disconnect_cache()
{
	if (pec_cache != NULL)
		ttlmap_free(pec_cache);
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
lookupcache:
	prefix = malloc(plen);
	memcpy(prefix, pptr, plen);
	item = ttlmap_get(pec_cache, &(pec_item) {
		.qtype = querybuf->header.qtype,
		.pfxlen = plen,
		.prefix = prefix
	});
	free(prefix);
	if (item == NULL) {
		goto missed;
	}
	switch (item->value[0]) {
		// 0 jump
		// 1 value
	case 0: {
		cn = item->value[2];
		plen = item->value[1];
		if (cn < querybuf->header.mincn) {
			ansbuf->header.id = querybuf->header.id;
			ansbuf->header.aa = 0;
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
		int vlen = item->vallen - 3;
		*alen = vlen;
		ins_ans_buf* cached_answer_ptr = (ins_ans_buf*)(item->value + 3);
		memcpy(ansbuf->buf + INS_AHEADERSIZE, cached_answer_ptr->buf + INS_AHEADERSIZE, vlen - INS_AHEADERSIZE);
		ansbuf->header.exacn = cached_answer_ptr->header.exacn;
		ansbuf->header.exaplen = cached_answer_ptr->header.exaplen;
		ansbuf->header.ancount = cached_answer_ptr->header.ancount;
		ansbuf->header.aa = 0;
		ansbuf->header.id = querybuf->header.id;
		return 0; // cache hit!
	}
	default: exit(2); break;
	}
missed:
	*alen = INS_AHEADERSIZE;
	if (firstlookup) {
		return -2; // cache miss.
	}
		
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
	if (pec_cache == NULL || expiretime <= 0) return -2;
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
	pec_item *pitem;

	if (insprefix_check_withmaxcn(pptr, querybuf->header.qnlen, querybuf->header.maxcn, &cn, &plen) < 0)
		return -2;
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
			
			pitem = ttlmap_set(pec_cache, &(pec_item){
				.qtype = querybuf->header.qtype,
				.pfxlen = curlen,
				.vallen = 3,
				.prefix = prefixmem,
				.value = valmem}, expiretime*1000);
			if (pitem != NULL) {
				free(pitem->prefix);
				free(pitem->value);
			}
		}
	}
	valueptr = valuebuf;
	*valueptr++ = 1; 
	*valueptr++ = exaplen;
	*valueptr++ = exacn;

	prefixmem = malloc(curlen);
	memcpy(prefixmem, pptr, curlen);
	valmem = malloc(3 + alen);
	memcpy(valmem, valuebuf, 3);
	memcpy(valmem + 3, ansbuf->buf, alen);
	pitem = ttlmap_set(pec_cache, &(pec_item){
		.qtype = querybuf->header.qtype,
		.pfxlen = curlen,
		.vallen = 3 + alen,
		.prefix = prefixmem,
		.value = valmem}, expiretime*1000);
	if (pitem != NULL) {
		free(pitem->prefix);
		free(pitem->value);
	}
	return 0;
}