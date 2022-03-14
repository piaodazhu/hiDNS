#ifndef INS_LOCALCACHE_H
#define INS_LOCALCACHE_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include "ins_msgformat.h"
#include "ins_prefix.h"

/*
 * cached key-value:
 * TYPE (1 A : 5 CNAME):NAME (/xx/yy/)  ---> TYPE(0 empty : 1 jump : 2 value) EXAPLEN ANCOUNT VALUEBUF
 * for example:
 * 	1:/edu/bit/lab101/news/  ----> 1 16
 * 	1:/edu/bit/lab101/  ---->  2 16 2 {ans1, ans2}
 */

int
ins_connect_cache();

int
ins_disconnect_cache();

// return -1 if not found, or return ancount
int
ins_get_entries_fromcache(const ins_qry_buf* querybuf, ins_ans_buf* ansbuf, int* alen);


int
ins_put_entries_tocache(const ins_qry_buf* querybuf, const ins_ans_buf* ansbuf, int alen, int expiretime);



#endif