#include <stdio.h>
#include <sys/time.h>

#include "hresolv.h"

int
ins_prefixdomainname2prefix(const char* domainname, int dlen, char* prefix, int plen)
{
	if (dlen > plen || dlen >= INS_PFXMAXSIZE)
		return -1;
	if (domainname[dlen - 1] == '.') --dlen;
	
	plen = dlen + 2;
	
	char buf[INS_PFXMAXSIZE];
	char *reverse_ptr = buf + INS_PFXMAXSIZE;
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

int 
insprefix_countcomponents(const char* prefix, int plen)
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

struct hostent* 
ins_gethostbyprefix(const char* prefix, const char* nameserver)
{
	int plen = strlen(prefix);
	if (plen >= INS_PFXMAXSIZE) return NULL;
	int cnum = 0;
	if (prefix[plen - 1] != '/') {
		char buf[INS_PFXMAXSIZE];
		memcpy(buf, prefix, plen);
		buf[plen] = '/';
		cnum = insprefix_countcomponents(buf, plen + 1);
	}
	cnum = insprefix_countcomponents(prefix, strlen(prefix));
	if (cnum < 0) {
		printf("[x] wrong args!\n");
		return NULL;
	}
	return ins_gethostbyname(prefix, nameserver, cnum, cnum);
}

struct hostent* 
ins_gethostbyname(const char* name, const char* nameserver, 
			int mincomponentcount, int maxcomponentcount)
{
	maxcomponentcount = maxcomponentcount > 8? 8 : maxcomponentcount;
	mincomponentcount = maxcomponentcount < 0? 0 : mincomponentcount;
	if (maxcomponentcount < mincomponentcount) {
		printf("[x] wrong args!\n");
		return NULL;
	}

	struct hostent* ht;
	int h_name_idx = 0, h_alias_idx = 0, h_addr_idx = 0;
	int i, n, ret;
	unsigned char *ptr, *bound;
	char prefixbuf[INS_PFXMAXSIZE];
	const char *lastname;
	int lastnamelen;
	
	ins_qry_buf qbuf;
	ins_ans_buf abuf;
	ins_ans_entry aentry;
	
	int qlen = ins_init_query_buf(&qbuf, qbuf.buf + INS_UDPMAXSIZE, name, strlen(name));
	qbuf.header.qtype = INS_T_A;
	qbuf.header.maxcn = maxcomponentcount;
	qbuf.header.mincn = mincomponentcount;

	int alen = sizeof(ins_ans_buf);
	int cacheret = ins_get_entries_fromcache(&qbuf, &abuf, &alen);

	switch (cacheret)
	{
	case -2:
		break;
	case -1:
	case 0:
		// printf("[+] cache hit\n");
		goto process_ans;
	default:
		qbuf.header.mincn = qbuf.header.maxcn = ((cacheret >> 8) & 0x0f);
	}

	// not connect cache or cache missed.
		// printf("[+] cache missed\n");
	struct sockaddr_in nserver;
	nserver.sin_family = AF_INET;
	nserver.sin_port = htons(5553);
	nserver.sin_addr.s_addr = inet_addr(nameserver);
	
	ret = ins_resolv(&nserver, &qbuf, qlen, &abuf, &alen);
	ins_put_entries_tocache(&qbuf, &abuf, alen, get_ins_ans_ttl(&abuf));
	if (ret != 0) 
		return NULL;
		
process_ans:
	ht = (struct hostent*) malloc (sizeof(struct hostent));
	n = abuf.header.ancount;
	printf("n = %d, exaplen = %d, alen = %d\n", n, abuf.header.exaplen, alen);
	ptr = abuf.buf + INS_AHEADERSIZE + abuf.header.exaplen;
	bound = abuf.buf + alen;
	printf("prefix = %.*s\n", abuf.header.exaplen, abuf.buf + INS_AHEADERSIZE);
	ht->h_name = malloc(INS_PFXMAXSIZE);
	ht->h_aliases = malloc(8 * sizeof(char*));
	ht->h_addr_list = malloc(8 * sizeof(in_addr_t*));
	ht->h_addrtype = AF_INET;
	ht->h_length = 0;

	lastname = name;
	lastnamelen = abuf.header.exaplen;
	for (i = 0; i < n; i++) {
		// printf("tag1\n");
		ptr += get_ins_ans_entry(ptr, bound, &aentry);
		// printf("tag2:%d, %d\n", aentry.type, aentry.length);
		switch (aentry.type) {
		case INS_T_A: {
			if (h_name_idx == 0) {
				memcpy(ht->h_name, lastname, lastnamelen);
				ht->h_name[lastnamelen] = 0;
				h_name_idx = 1;
			}
			ht->h_addr_list[h_addr_idx] = malloc(sizeof(in_addr_t));
			memcpy(ht->h_addr_list[h_addr_idx++], aentry.value, aentry.length);
			// printf("tag3\n");
			break;
		}
		case INS_T_CNAME: {
			ht->h_aliases[h_alias_idx] = malloc(lastnamelen + 1);
			memcpy(ht->h_aliases[h_alias_idx], lastname, lastnamelen);
			ht->h_aliases[h_alias_idx++][lastnamelen] = 0;
			// convert all cname to prefix for formal consistency
			ret = ins_prefixdomainname2prefix(aentry.value, aentry.length, prefixbuf, INS_PFXMAXSIZE);
			if (ret > 0) {
				lastnamelen = ret;
				lastname = prefixbuf;
			}
			break;
		}
		default: break;
		}
	}

	ht->h_addr_list[h_addr_idx] = NULL;
	ht->h_aliases[h_alias_idx] = NULL;
	return ht;
}

in_addr_t**
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

char**
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

char**
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

struct sockaddr**
ins_getadminbyname(const char* name, const char* nameserver, 
			int mincomponentcount, int maxcomponentcount)
{
	struct sockaddr_in nserver;
	nserver.sin_family = AF_INET;
	nserver.sin_port = htons(5553);
	nserver.sin_addr.s_addr = inet_addr(nameserver);
	return ins_getadminbyname2(name, strlen(name), &nserver, 
			mincomponentcount, maxcomponentcount);
}

in_addr_t**
ins_getaddrbyname2(const char* name, int nlen, const struct sockaddr_in *nameserver, 
			int mincomponentcount, int maxcomponentcount)
{
	hidns_resolv_ans_t *ans = ins_resolv2(name, nlen, nameserver, mincomponentcount, maxcomponentcount, INS_T_A, RESOLV_FLAG_DEFAULT);
	if (ans == NULL) return NULL;
	// printf("TAG2\n");
	int i, len, size = ans->rrsetsize;
	in_addr_t** addrlist = (in_addr_t**)malloc((size + 1) * sizeof(in_addr_t*));
	addrlist[size] = NULL;
	int j = 0;

	for (i = 0; i < size; i++) {
		addrlist[i] = NULL;
		len = get_ins_entry_len(ans->rrset_lst[i] + 2);
		if (len != sizeof(in_addr_t)) {
			continue;
		}
		// printf("len = %d\n", len);
		addrlist[j] = malloc(len);
		memcpy(addrlist[j++], ans->rrset_lst[i] + 2 + INS_ENTRYFIXLEN, len);
	}
	// printf("TAG3\n");
	free_hidns_resolv_ans(ans);
	return addrlist;
}

char**
ins_getnsbyname2(const char* name, int nlen, const struct sockaddr_in *nameserver,
			int mincomponentcount, int maxcomponentcount)
{
	hidns_resolv_ans_t *ans = ins_resolv2(name, nlen, nameserver, mincomponentcount, maxcomponentcount, INS_T_NS, RESOLV_FLAG_DEFAULT);
	if (ans == NULL) return NULL;
	int i, len, size = ans->rrsetsize;
	char** nslist = (char**)malloc((size + 1) * sizeof(char*));
	nslist[size] = NULL;
	
	for (i = 0; i < size; i++) {
		len = get_ins_entry_len(ans->rrset_lst[i] + 2);
		// printf("len = %d\n", len);
		nslist[i] = malloc(len + 1);
		nslist[i][len] = 0;
		memcpy(nslist[i], ans->rrset_lst[i] + 2 + INS_ENTRYFIXLEN, len);
	}
	// printf("TAG3\n");
	free_hidns_resolv_ans(ans);
	return nslist;
}

char**
ins_gettxtbyname2(const char* name, int nlen, const struct sockaddr_in *nameserver,
			int mincomponentcount, int maxcomponentcount)
{
	hidns_resolv_ans_t *ans = ins_resolv2(name, nlen, nameserver, mincomponentcount, maxcomponentcount, INS_T_TXT, RESOLV_FLAG_DEFAULT);
	if (ans == NULL) return NULL;
	// printf("TAG2\n");
	int i, len, size = ans->rrsetsize;
	char** txtlist = (char**)malloc((size + 1) * sizeof(char*));
	txtlist[size] = NULL;
	
	for (i = 0; i < size; i++) {
		len = get_ins_entry_len(ans->rrset_lst[i] + 2);
		// printf("len = %d\n", len);
		txtlist[i] = malloc(len + 1);
		txtlist[i][len] = 0;
		memcpy(txtlist[i], ans->rrset_lst[i] + 2 + INS_ENTRYFIXLEN, len);
	}
	// printf("TAG3\n");
	free_hidns_resolv_ans(ans);
	return txtlist;
}

struct sockaddr**
ins_getadminbyname2(const char* name, int nlen, const struct sockaddr_in *nameserver, 
			int mincomponentcount, int maxcomponentcount)
{
	hidns_resolv_ans_t *ans = ins_resolv2(name, nlen, nameserver, mincomponentcount, maxcomponentcount, INS_T_HADMIN, RESOLV_FLAG_DEFAULT);
	if (ans == NULL) return NULL;
	// printf("TAG2\n");
	int i, len, size = ans->rrsetsize;
	struct sockaddr** addrlist = (struct sockaddr**)malloc((size + 1) * sizeof(struct sockaddr*));
	addrlist[size] = NULL;
	int j = 0;
	unsigned char sockbuf[2 * sizeof(struct sockaddr)];
	unsigned char socklen;
	for (i = 0; i < size; i++) {
		addrlist[i] = NULL;
		len = get_ins_entry_len(ans->rrset_lst[i] + 2);
		// printf("len = %d\n", len);
		if (BASE64_DECODE_OUT_SIZE(len) > 2 * sizeof(struct sockaddr)) {
			continue;
		}
		socklen = base64_decode(ans->rrset_lst[i] + 2 + INS_ENTRYFIXLEN, len, sockbuf);
		if (sizeof(struct sockaddr) != socklen) {
			continue;
		}
		addrlist[j] = malloc(sizeof(struct sockaddr));
		memcpy(addrlist[j++], sockbuf, socklen);
	}
	// printf("TAG3\n");
	free_hidns_resolv_ans(ans);
	return addrlist;
}

int ins_resolv(const struct sockaddr_in *nameserver,
	const ins_qry_buf *qbuf, int qlen, ins_ans_buf *abuf, int *alen)
{
#ifdef INS_UDP_SOCK

	// char logbuf[256];
	// int logptr = 0;
	// logptr += sprintf(logbuf + logptr, "---- query ----\n");
	// logptr += sprintf(logbuf + logptr, "id = %u\n", ntohl(qbuf->header.id));
	// logptr += sprintf(logbuf + logptr, "aa = %d, ", qbuf->header.aa);
	// logptr += sprintf(logbuf + logptr, "tc = %d, ", qbuf->header.tc);
	// logptr += sprintf(logbuf + logptr, "rd = %d, ", qbuf->header.rd);
	// logptr += sprintf(logbuf + logptr, "ra = %d\n", qbuf->header.ra);
	// logptr += sprintf(logbuf + logptr, "cd = %d, ", qbuf->header.cd);
	// logptr += sprintf(logbuf + logptr, "ad = %d, ", qbuf->header.ad);
	// logptr += sprintf(logbuf + logptr, "od = %d\n", qbuf->header.od);
	// logptr += sprintf(logbuf + logptr, "hoplimit = %d, ", qbuf->header.hoplimit);
	// logptr += sprintf(logbuf + logptr, "mincn = %d, ", qbuf->header.mincn);
	// logptr += sprintf(logbuf + logptr, "maxcn = %d\n", qbuf->header.maxcn);

	// logptr += sprintf(logbuf + logptr, "qtype = %d, ", qbuf->header.qtype);
	// logptr += sprintf(logbuf + logptr, "qnlen = %d\n", qbuf->header.qnlen);
	// logptr += sprintf(logbuf + logptr, "name: %.*s\n", qbuf->header.qnlen, qbuf->buf + INS_QHEADERSIZE);
	// printf("%.*s", logptr, logbuf);

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct timeval tv;
	tv.tv_sec = 2;
	tv.tv_usec = 0;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
	if (sendto(fd, qbuf->buf, qlen, 0, (struct sockaddr*)nameserver, sizeof(struct sockaddr_in)) < 0 )
        {
            perror("send:");  
            exit(3);   
        }
	int len;
	*alen = recvfrom(fd, abuf->buf, INS_UDPMAXSIZE, 0, (struct sockaddr*)nameserver, &len);
	close(fd);
#else

#ifdef INS_UNIX_SOCK
	struct sockaddr_un unixserver;
	unixserver.sun_family = AF_UNIX;
	strcpy(unixserver.sun_path, "/tmp/hidns.sock");
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	connect(fd, (struct sockaddr*) &unixserver, sizeof(struct sockaddr_un));
#else
	int fd = Socket(AF_INET, SOCK_STREAM, 0);
	Connect(fd, (struct sockaddr*)nameserver, sizeof(struct sockaddr_in));
#endif	
	Write(fd, qbuf->buf, qlen);
	*alen = Read(fd, abuf->buf, INS_UDPMAXSIZE);
	close(fd);

#endif
	if (*alen < INS_AHEADERSIZE) {
		return -1; // timeout
	}	
	if (qbuf->header.id != abuf->header.id) {
		return -2; // malform answer
	}

	return (int)abuf->header.rcode;
}

hidns_resolv_ans_t*
ins_resolv2(const char* name, int nlen, const struct sockaddr_in *nameserver,
			int mincomponentcount, int maxcomponentcount, 
			int qtype, int flags)
{
	// TBD: flag can control cache|verify policy
	maxcomponentcount = maxcomponentcount > 8? 8 : maxcomponentcount;
	mincomponentcount = maxcomponentcount < 0? 0 : mincomponentcount;
	if (maxcomponentcount < mincomponentcount) {
		printf("[x] wrong args!\n");
		return NULL;
	}
	
	// in_addr_t *addrlist, *addrlistptr;
	hidns_resolv_ans_t* ans;
	int i, n, ret;
	unsigned char *ptr, *bound;

	ins_qry_buf qbuf;
	ins_ans_buf abuf;
	ins_ans_entry aentry;
	
	int qlen = ins_init_query_buf(&qbuf, qbuf.buf + INS_UDPMAXSIZE, name, strlen(name));
	qbuf.header.qtype = qtype;
	qbuf.header.maxcn = maxcomponentcount;
	qbuf.header.mincn = mincomponentcount;

	int alen = sizeof(ins_ans_buf);
	int cacheret = ins_get_entries_fromcache(&qbuf, &abuf, &alen);

	switch (cacheret)
	{
	case -2:
		break;
	case -1:
	case 0:
		// printf("[+] cache hit\n");
		goto cache_hit;
	default:
		qbuf.header.mincn = qbuf.header.maxcn = ((cacheret >> 8) & 0x0f);
	}

	// not connect cache or cache missed.
	// printf("[+] cache missed\n");

	qbuf.header.cd = ((flags & RESOLV_FLAG_TRUST_AD) != 0);	
	qbuf.header.cd = ((flags & RESOLV_FLAG_MUST_VERIFY) != 0);
	
	if ((flags & RESOLV_FLAG_OVER_DTLS) != 0) {
	// if (0) {
		qbuf.header.od = 1;
		// append nameserver's IP address to query, then send query to DTLS proxy. ONLY IPv4 so far.
		char *ptr = qbuf.buf + INS_QHEADERSIZE + qbuf.header.qnlen;
		memcpy(ptr, (char*)&nameserver->sin_addr, sizeof(nameserver->sin_addr));
		qlen += sizeof(nameserver->sin_addr);

		struct sockaddr_in dlts_proxy;
		dlts_proxy.sin_family = AF_INET;
		dlts_proxy.sin_port = htons(5556);
		dlts_proxy.sin_addr.s_addr = inet_addr("127.0.0.1");

		ret = ins_resolv(&dlts_proxy, &qbuf, qlen, &abuf, &alen);
	} else {
		ret = ins_resolv(nameserver, &qbuf, qlen, &abuf, &alen);
	}
	
	if (ret != 0) 
		return NULL;
	
	ans = new_hidns_resolv_ans(&abuf);
	if (ans == NULL) {
		return NULL;
	}

	// verify
	if (((flags & RESOLV_FLAG_MUST_VERIFY) != 0) || 
		((flags & RESOLV_FLAG_TRUST_AD) != 0 && abuf.header.ad == 0)) {
		// TBD: do verify
		// if not valid, return NULL
		// printf("[TAG] do verify\n");
		if (verify_hidns_resolv_ans(ans) != 0) {
			// printf("[TAG] verify failed\n");
			free_hidns_resolv_ans(ans);
			return NULL;
		}
		// if valid, decide cache and return ans
		if ((flags & RESOLV_FLAG_AUTO_CACHE) != 0) {
			ins_put_entries_tocache(&qbuf, &abuf, alen, get_ins_ans_ttl(&abuf));
		}
		return ans;
	}
	// cache
	if ((flags & RESOLV_FLAG_AUTO_CACHE) != 0) {
		ins_put_entries_tocache(&qbuf, &abuf, alen, get_ins_ans_ttl(&abuf));
	}
	return ans;	
cache_hit:
	ans = new_hidns_resolv_ans(&abuf);
	// printf("TAG1\n");
	return ans;
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
ins_free_addrlist(in_addr_t** alist)
{
	if (alist != NULL) {
		in_addr_t** ptr = alist;
		while (*ptr != NULL) {
			free(*ptr);
			++ptr;
		}
		free(alist);
	}
}

void
ins_free_sockaddrlist(struct sockaddr** slist)
{
	if (slist != NULL) {
		struct sockaddr** ptr = slist;
		while (*ptr != NULL) {
			free(*ptr);
			++ptr;
		}
		free(slist);
	}
}

void
ins_free_buflist(char** blist)
{
	if (blist != NULL) {
		char** ptr = blist;
		while (*ptr != NULL) {
			free(*ptr);
			++ptr;
		}
		free(blist);
	}
}
