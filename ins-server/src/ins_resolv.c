#include "ins_resolv.h"
#include <stdio.h>
#include <sys/time.h>

int
ins_prefixdomainname2prefix(const char* domainname, int dlen, char* prefix, int plen)
{
	if (dlen > plen || dlen > 255)
		return -1;
	if (domainname[dlen - 1] == '.') --dlen;
	
	plen = dlen + 2;
	
	char buf[256];
	char *reverse_ptr = buf + 256;
	int idx = 0;
	int pre_dot = -1;
	int clen = 0;
	int cnum = 0;
	while (idx < dlen) {
		if (domainname[idx] == '.') {
			clen = idx - pre_dot - 1;
			++cnum;
			if (clen > 63) return -2;
			if (cnum > 8) return -3;
			*(--reverse_ptr) = '/';
			reverse_ptr -= clen;
			memcpy(reverse_ptr, domainname + pre_dot + 1, clen);
			pre_dot = idx;
		} else if (!((domainname[idx] >= '0' && domainname[idx] <= '9')
					 || (domainname[idx] >= 'a' && domainname[idx] <= 'z') 
					 || domainname[idx] == '-')) {
			return -4;
		}
		idx++;
	}
	clen = idx - pre_dot - 1;
	*(--reverse_ptr) = '/';
	reverse_ptr -= clen;
	memcpy(reverse_ptr, domainname + pre_dot + 1, clen);
	*(--reverse_ptr) = '/';
	memcpy(prefix, reverse_ptr, plen);
	prefix[plen] = 0;
	return plen;
}

int insprefix_count_components(const char* prefix, int plen)
{
	if (prefix[0] != '/' || prefix[plen - 1] != '/') return -1;
	int idx = 1;
	int cnum = 0, clen = 0;
	char ch;
	while (idx++ < plen) {
		ch = prefix[idx];
		if (ch == '/') {
			++cnum;
			if (cnum > 8) return -3;
			if (clen > 63) return -4;
			clen = 0;
		} else {
			++clen;
		}
		if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z') || ch == '-')) {
			return -2;
		}
	}
	return cnum;
}

struct hostent* ins_gethostbyprefix(const char* prefix, const char* nameserver)
{
	int plen = strlen(prefix);
	if (plen > 255) return NULL;
	int cnum = 0;
	if (prefix[plen - 1] != '/') {
		char buf[256];
		memcpy(buf, prefix, plen);
		buf[plen] = '/';
		cnum = insprefix_count_components(buf, plen + 1);
	}
	cnum = insprefix_count_components(prefix, strlen(prefix));
	if (cnum < 0) {
		printf("[x] wrong args!\n");
		return NULL;
	}
	return ins_gethostbyname(prefix, nameserver, cnum, cnum);
}

struct hostent* ins_gethostbyname(const char* name, const char* nameserver, 
			int mincomponentcount, int maxcomponentcount)
{
	maxcomponentcount = maxcomponentcount > 8? 8 : maxcomponentcount;
	mincomponentcount = maxcomponentcount < 0? 0 : mincomponentcount;
	if (maxcomponentcount < mincomponentcount) {
		printf("[x] wrong args!\n");
		return NULL;
	}
	
	ins_qry_buf qbuf;
	
	int qlen = ins_init_query_buf(&qbuf, qbuf.buf + INS_MAXPKTSIZE, name, strlen(name));
	qbuf.header.qtype = INS_T_A;
	qbuf.header.maxcn = maxcomponentcount;
	qbuf.header.mincn = mincomponentcount;
	
	struct sockaddr_in nserver;
	nserver.sin_family = AF_INET;
	nserver.sin_port = htons(5553);
	nserver.sin_addr.s_addr = inet_addr(nameserver);

	ins_ans_buf abuf;
	int alen = sizeof(ins_ans_buf);

	int ret = ins_resolv(&nserver, &qbuf, qlen, &abuf, &alen);
	if (ret != 0) 
		return NULL;

	struct hostent* ht = (struct hostent*) malloc (sizeof(struct hostent));
	int i, n = abuf.header.ancount;
	unsigned char* ptr = abuf.buf + INS_AHEADERSIZE;
	unsigned char* bound = abuf.buf + alen;
	ins_ans_entry aentry;

	ht->h_name = malloc(256);
	int h_name_idx = 0;
	ht->h_aliases = malloc(8 * sizeof(char*));
	int h_alias_idx = 0;
	ht->h_addr_list = malloc(8 * sizeof(in_addr_t*));
	int h_addr_idx = 0;
	ht->h_addrtype = AF_INET;
	ht->h_length = 0;

	const char* lastname = name;
	int lastnamelen = abuf.header.exaplen;
	char prefixbuf[256];
	for (i = 0; i < n; i++) {
		ptr += get_ins_ans_entry(ptr, bound, &aentry);
		switch (aentry.type) {
		case INS_T_A: {
			if (h_name_idx == 0) {
				memcpy(ht->h_name, lastname, lastnamelen);
				ht->h_name[lastnamelen] = 0;
				h_name_idx = 1;
			}
			ht->h_addr_list[h_addr_idx] = malloc(sizeof(in_addr_t));
			memcpy(ht->h_addr_list[h_addr_idx++], aentry.value, aentry.length);
			break;
		}
		case INS_T_CNAME: {
			ht->h_aliases[h_alias_idx] = malloc(lastnamelen + 1);
			memcpy(ht->h_aliases[h_alias_idx], lastname, lastnamelen);
			ht->h_aliases[h_alias_idx++][lastnamelen] = 0;
			// convert all cname to prefix for formal consistency
			int ret = ins_prefixdomainname2prefix(aentry.value, aentry.length, prefixbuf, 256);
			if (ret > 0) {
				lastnamelen = ret;
				lastname = prefixbuf;
			}
			break;
		}
		default: break;
		}
	}
	
	return ht;
}


in_addr_t*
ins_getaddrbyname(const char* name, const char* nameserver, 
			int mincomponentcount, int maxcomponentcount)
{
	struct sockaddr_in nserver;
	nserver.sin_family = AF_INET;
	nserver.sin_port = htons(5553);
	nserver.sin_addr.s_addr = inet_addr(nameserver);
	return ins_getaddrbyname2(name, strlen(name), &nserver, 
			mincomponentcount, maxcomponentcount);	
}


ins_ans_entry*
ins_getnsbyname(const char* name, const char* nameserver, 
			int mincomponentcount, int maxcomponentcount)
{
	struct sockaddr_in nserver;
	nserver.sin_family = AF_INET;
	nserver.sin_port = htons(5553);
	nserver.sin_addr.s_addr = inet_addr(nameserver);
	return ins_getnsbyname2(name, strlen(name), &nserver, 
			mincomponentcount, maxcomponentcount);
}


ins_ans_entry*
ins_gettxtbyname(const char* name, const char* nameserver, 
			int mincomponentcount, int maxcomponentcount)
{
	struct sockaddr_in nserver;
	nserver.sin_family = AF_INET;
	nserver.sin_port = htons(5553);
	nserver.sin_addr.s_addr = inet_addr(nameserver);
	return ins_gettxtbyname2(name, strlen(name), &nserver, 
			mincomponentcount, maxcomponentcount);
}


ins_ans_entry*
ins_getsoabyname(const char* name, const char* nameserver, 
			int mincomponentcount, int maxcomponentcount)
{
	struct sockaddr_in nserver;
	nserver.sin_family = AF_INET;
	nserver.sin_port = htons(5553);
	nserver.sin_addr.s_addr = inet_addr(nameserver);
	return ins_getsoabyname2(name, strlen(name), &nserver, 
			mincomponentcount, maxcomponentcount);
}

in_addr_t*
ins_getaddrbyname2(const char* name, int nlen, const struct sockaddr_in *nameserver, 
			int mincomponentcount, int maxcomponentcount)
{
	maxcomponentcount = maxcomponentcount > 8? 8 : maxcomponentcount;
	mincomponentcount = maxcomponentcount < 0? 0 : mincomponentcount;
	if (maxcomponentcount < mincomponentcount) {
		printf("[x] wrong args!\n");
		return NULL;
	}
	
	ins_qry_buf qbuf;
	
	int qlen = ins_init_query_buf(&qbuf, qbuf.buf + INS_MAXPKTSIZE, name, strlen(name));
	qbuf.header.qtype = INS_T_A;
	qbuf.header.maxcn = maxcomponentcount;
	qbuf.header.mincn = mincomponentcount;

	ins_ans_buf abuf;
	int alen = sizeof(ins_ans_buf);

	int ret = ins_resolv(nameserver, &qbuf, qlen, &abuf, &alen);
	if (ret != 0) 
		return NULL;
	
	in_addr_t *addrlist = (in_addr_t*) malloc (abuf.header.ancount * sizeof(in_addr_t));
	in_addr_t *addrlistptr = addrlist;
	int i, n = abuf.header.ancount;
	unsigned char* ptr = abuf.buf + INS_AHEADERSIZE;
	unsigned char* bound = abuf.buf + alen;
	ins_ans_entry aentry;

	for (i = 0; i < n; i++) {
		ptr += get_ins_ans_entry(ptr, bound, &aentry);
		if (aentry.type == INS_T_A) {
			*addrlistptr++ = *((in_addr_t*)aentry.value);
		}
	}
	*addrlistptr = 0;
	return addrlist;
}


ins_ans_entry*
ins_getnsbyname2(const char* name, int nlen, const struct sockaddr_in *nameserver,
			int mincomponentcount, int maxcomponentcount)
{
	maxcomponentcount = maxcomponentcount > 8? 8 : maxcomponentcount;
	mincomponentcount = maxcomponentcount < 0? 0 : mincomponentcount;
	if (maxcomponentcount < mincomponentcount) {
		printf("[x] wrong args!\n");
		return NULL;
	}
	
	ins_qry_buf qbuf;
	
	int qlen = ins_init_query_buf(&qbuf, qbuf.buf + INS_MAXPKTSIZE, name, strlen(name));
	qbuf.header.qtype = INS_T_NS;
	qbuf.header.maxcn = maxcomponentcount;
	qbuf.header.mincn = mincomponentcount;

	ins_ans_buf abuf;
	int alen = sizeof(ins_ans_buf);

	int ret = ins_resolv(nameserver, &qbuf, qlen, &abuf, &alen);
	if (ret != 0) 
		return NULL;
	
	ins_ans_entry *aentry = (ins_ans_entry *) malloc (sizeof(ins_ans_entry));
	int i, n = abuf.header.ancount;
	unsigned char* ptr = abuf.buf + INS_AHEADERSIZE;
	unsigned char* bound = abuf.buf + alen;
	ins_ans_entry entrybuf;

	for (i = 0; i < n; i++) {
		ptr += get_ins_ans_entry(ptr, bound, &entrybuf);
		if (entrybuf.type == INS_T_NS) {
			aentry->ttl = entrybuf.ttl;
			aentry->type = entrybuf.type;
			aentry->value = malloc(256);

			ret = ins_prefixdomainname2prefix(entrybuf.value, entrybuf.length, aentry->value, 256);
			if (ret > 0) {
				aentry->length = ret;
			} else {
				printf("[x] can't parse NS!\n");
				free(aentry->value);
				free(aentry);
				return NULL;
			}
			break;
		}
	}

	return aentry;
}


ins_ans_entry*
ins_gettxtbyname2(const char* name, int nlen, const struct sockaddr_in *nameserver,
			int mincomponentcount, int maxcomponentcount)
{
	maxcomponentcount = maxcomponentcount > 8? 8 : maxcomponentcount;
	mincomponentcount = maxcomponentcount < 0? 0 : mincomponentcount;
	if (maxcomponentcount < mincomponentcount) {
		printf("[x] wrong args!\n");
		return NULL;
	}
	
	ins_qry_buf qbuf;
	
	int qlen = ins_init_query_buf(&qbuf, qbuf.buf + INS_MAXPKTSIZE, name, strlen(name));
	qbuf.header.qtype = INS_T_TXT;
	qbuf.header.maxcn = maxcomponentcount;
	qbuf.header.mincn = mincomponentcount;

	ins_ans_buf abuf;
	int alen = sizeof(ins_ans_buf);

	int ret = ins_resolv(nameserver, &qbuf, qlen, &abuf, &alen);
	if (ret != 0) 
		return NULL;
	
	ins_ans_entry *aentry = (ins_ans_entry *) malloc (sizeof(ins_ans_entry));
	int i, n = abuf.header.ancount;
	unsigned char* ptr = abuf.buf + INS_AHEADERSIZE;
	unsigned char* bound = abuf.buf + alen;
	ins_ans_entry entrybuf;

	for (i = 0; i < n; i++) {
		ptr += get_ins_ans_entry(ptr, bound, &entrybuf);
		if (entrybuf.type == INS_T_TXT) {
			aentry->ttl = entrybuf.ttl;
			aentry->type = entrybuf.type;
			aentry->length = entrybuf.length;
			aentry->value = malloc(aentry->length);
			memcpy(aentry->value, entrybuf.value, aentry->length);
			break;
		}
	}

	return aentry;
}


ins_ans_entry*
ins_getsoabyname2(const char* name, int nlen, const struct sockaddr_in *nameserver,
			int mincomponentcount, int maxcomponentcount)
{
	maxcomponentcount = maxcomponentcount > 8? 8 : maxcomponentcount;
	mincomponentcount = maxcomponentcount < 0? 0 : mincomponentcount;
	if (maxcomponentcount < mincomponentcount) {
		printf("[x] wrong args!\n");
		return NULL;
	}
	
	ins_qry_buf qbuf;
	
	int qlen = ins_init_query_buf(&qbuf, qbuf.buf + INS_MAXPKTSIZE, name, strlen(name));
	qbuf.header.qtype = INS_T_SOA;
	qbuf.header.maxcn = maxcomponentcount;
	qbuf.header.mincn = mincomponentcount;

	ins_ans_buf abuf;
	int alen = sizeof(ins_ans_buf);

	int ret = ins_resolv(nameserver, &qbuf, qlen, &abuf, &alen);
	if (ret != 0) 
		return NULL;

	ins_ans_entry *aentry = (ins_ans_entry *) malloc (sizeof(ins_ans_entry));
	int i, n = abuf.header.ancount;
	unsigned char* ptr = abuf.buf + INS_AHEADERSIZE;
	unsigned char* bound = abuf.buf + alen;
	ins_ans_entry entrybuf;

	for (i = 0; i < n; i++) {
		ptr += get_ins_ans_entry(ptr, bound, &entrybuf);
		if (entrybuf.type == INS_T_SOA) {
			aentry->ttl = entrybuf.ttl;
			aentry->type = entrybuf.type;
			aentry->value = malloc(256);

			ret = ins_prefixdomainname2prefix(entrybuf.value, entrybuf.length, aentry->value, 256);
			if (ret > 0) {
				aentry->length = ret;
			} else {
				printf("[x] can't parse SOA!\n");
				free(aentry->value);
				free(aentry);
				return NULL;
			}
			break;
		}
	}

	return aentry;
}


int ins_resolv(const struct sockaddr_in *nameserver,
	const ins_qry_buf *qbuf, int qlen, ins_ans_buf *abuf, int *alen)
{
	int fd = Socket(AF_INET, SOCK_STREAM, 0);
	Connect(fd, (struct sockaddr*)nameserver, sizeof(struct sockaddr_in));
	Write(fd, qbuf->buf, qlen);
	*alen = Read(fd, abuf->buf, INS_MAXPKTSIZE);
	close(fd);
	
	if (*alen < INS_AHEADERSIZE || qbuf->header.id != abuf->header.id) {
		return 8;
	}

	return (int)abuf->header.rcode;
}

void
ins_free_hostent(struct hostent* ht)
{
	if (ht == NULL) return;
	free(ht->h_name);
	if (ht->h_aliases != NULL) {
		char **ptr = NULL;
		for (ptr = ht->h_aliases; ptr != NULL; ++ptr) {
			free(*ptr);
		}
		free(ht->h_aliases);
	}
	if (ht->h_addr_list != NULL) {
		char **ptr = NULL;
		for (ptr = ht->h_addr_list; ptr != NULL; ++ptr) {
			free(*ptr);
		}
		free(ht->h_addr_list);
	}
	free(ht);
}

void
ins_free_aentry(ins_ans_entry* aentry)
{
	if (aentry != NULL) {
		if (aentry->length != 0) {
			free(aentry->value);
		}
		free(aentry);
	}
}

void
ins_free_addrlist(in_addr_t* alist)
{
	if (alist != NULL) {
		free(alist);
	}
}
