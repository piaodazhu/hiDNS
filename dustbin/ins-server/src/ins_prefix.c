#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ins_prefix.h"

int
insprefix_check_withmaxcn(const char* name, int nlen, int maxcn, int* exacn, int* exaplen)
{
	if (*name != '/') {
		*exaplen = 0;
		*exacn = 0;
		return CHECKPREFIX_INVALID_SYMBOL;
	}

	int cur_idx = 0;
	int max_idx = nlen > 256?256:nlen;
	int last_splash = 0;
	int splash_num = 0;
	int clen = 0;
	while (splash_num <= maxcn && cur_idx < max_idx) {
		if (name[cur_idx] == '/') {
			clen = 0;

			last_splash = cur_idx;
			splash_num++;
		}
		else if (!((name[cur_idx] >= '0' && name[cur_idx] <= '9')
			|| (name[cur_idx] >= 'a' && name[cur_idx] <= 'z') 
			|| name[cur_idx] == '-'))
		{
			break;
		} 
		else {
			clen++;
		} 

		if (clen > 63) {
			break;
		}
		cur_idx++;
		
	}

	*exaplen = last_splash + 1;
	*exacn = splash_num - 1;
	return *exaplen;
}

int
insprefix_cn2plen_nocheck(const char* name, int nlen, int componentsnum)
{
	int idx = 1;
	int cnum = 0;
	while (cnum < componentsnum && idx < nlen) {
		if (name[idx] == '/') {
			cnum++;
		}
		idx++;
	}
	return cnum == componentsnum? idx : -1;
}

int
insprefix_prefix2domainname(const char* prefix, int plen, char* domainname, int dlen)
{
	if (*prefix != '/') return CHECKPREFIX_INVALID_SYMBOL;
	if (plen > 255) return CHECKPREFIX_TOOLONG_PREFIX;
	if (prefix[plen - 1] == '/') --plen;
	if (plen > dlen) return CHECKPREFIX_TOOLONG_PREFIX;
	char buf[256];
	char *reverse_ptr = buf + 256;
	int idx = 1;
	int pre_splash = 0;
	int clen = 0;
	int cnum = 0;
	while (idx < plen) {
		if (prefix[idx] == '/') {
			clen = idx - pre_splash - 1;
			++cnum;
			if (clen > 63) return CHECKPREFIX_TOOLONG_COMPONENT;
			if (cnum > 8) return CHECKPREFIX_TOOMANY_COMPONENT;
			// if (clen == 0) return CHECKPREFIX_EMPTY_COMPONENT;
			*(--reverse_ptr) = '.';
			reverse_ptr -= clen;
			memcpy(reverse_ptr, prefix + pre_splash + 1, clen);
			pre_splash = idx;
		} else if (!((prefix[idx] >= '0' && prefix[idx] <= '9')
					 || (prefix[idx] >= 'a' && prefix[idx] <= 'z') 
					 || prefix[idx] == '-')) {
			return CHECKPREFIX_INVALID_SYMBOL;
		}
		idx++;
	}
	clen = idx - pre_splash - 1;
	*(--reverse_ptr) = '.';
	reverse_ptr -= clen;
	memcpy(reverse_ptr, prefix + pre_splash + 1, clen);
	memcpy(domainname, reverse_ptr, plen);
	domainname[plen] = 0;
	return plen;
}

int
insprefix_prefix2domainname_nocheck(const char* prefix, int plen, char* domainname, int dlen)
{

	if (prefix[plen - 1] == '/') --plen;

	char buf[256];
	char *reverse_ptr = buf + 256;

	int idx = 1;
	int pre_splash = 0;
	int clen = 0;
	while (idx < plen) {
		if (prefix[idx] == '/') {
			clen = idx - pre_splash - 1;
			*(--reverse_ptr) = '.';
			reverse_ptr -= clen;
			memcpy(reverse_ptr, prefix + pre_splash + 1, clen);
			pre_splash = idx;
		}
		idx++;
	}
	clen = idx - pre_splash - 1;
	*(--reverse_ptr) = '.';
	reverse_ptr -= clen;

	memcpy(reverse_ptr, prefix + pre_splash + 1, clen);
	memcpy(domainname, reverse_ptr, plen);
	domainname[plen] = 0;
	return plen;
}