#ifndef HIINS_LOCALCACHE_H
#define HIINS_LOCALCACHE_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include "ins_msgformat.h"
#include "ins_prefix.h"

/*
 * cached key-value:
 * TYPE (1 A : 5 CNAME):NAME (/xx/yy/)  ---> TYPE(0 jump : 1 value) EXAPLEN EXACN VALUEBUF
 * for example:
 *                 k                           v
 * 	1:/edu/bit/lab101/news/  ---->        1 16
 * 	1:/edu/bit/lab101/       ---->    2 16 {ans_buf}
 * 
 * cached lookup result:
 * miss: return missed.
 * hit value: return value.
 * hit jump, then look up again. return value, exact or NOREC.
 * 	miss0:  NIL
 * 	miss1: query is (/a/b/c/d/e/, 2, 5), cache is (/a/b/c/d/e/f/, 3value, 4jump)
 * 	miss2: query is (/a/b/c/d/e/, 2, 5), cache is (/a/b/c/d/e/f/, 1value, 4jump)
 * 	value: query is (/a/b/c/d/e/, 2, 5), cache is (/a/b/c/d/e/f/, 3value, 6jump)
 * 	NOREC: query is (/a/b/c/d/e/, 2, 5), cache is (/a/b/c/d/e/f/, 1value, 6jump)
 * 	exact: query is (/a/b/c/d/e/, 2, 5), cache is (/a/b/c/d/e/f/, 3value, 6jump), but next lookup 3value missed.
 * ret miss = -2, NOREC = -1, value = 0, exact = (exacn, exaplen).
 */

typedef struct pec_item {
	unsigned short qtype;
	unsigned int pfxlen;
	unsigned int vallen;
	char *prefix;
	unsigned char* value;
}pec_item;

int
ins_connect_cache();

int
ins_disconnect_cache();

int
ins_get_entries_fromcache(const ins_qry_buf* querybuf, ins_ans_buf* ansbuf, int* alen);

int
ins_put_entries_tocache(const ins_qry_buf* querybuf, const ins_ans_buf* ansbuf, int alen, int expiretime);

#endif