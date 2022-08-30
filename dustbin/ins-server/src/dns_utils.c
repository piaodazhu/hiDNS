#include "dns_utils.h"


int 
dns_init(ins_qry_buf* ins_qbuf, res_state state, struct sockaddr_in nameserver)
{
	res_ninit(state);
	state->nscount = 1;
	memcpy(state->nsaddr_list, &nameserver, sizeof(nameserver));
	state->retry = 3;
	return 0;
}

int 
dns_resolve(ins_qry_buf* ins_qbuf, res_state state, unsigned char* domainname,
		answerbuf_t* dns_abuf, int* dns_abuflen)
{
	int class = C_IN;
	int type = ins_qbuf->header.qtype;
	int ret = res_nquery(state, domainname, class, type, dns_abuf->buf, *dns_abuflen);
	*dns_abuflen = ret;
	return *dns_abuflen;
}

int
dns_assembletxt(const unsigned char *in, unsigned short inlen, unsigned char *out, const unsigned char *bound)
{
	if (bound - out < inlen) return 0;
	unsigned char* dptr = out;
	const unsigned char* sptr = in;
	int datalen = 0, actuallen = 0;
	unsigned char txtlen = 0;
	while (datalen < inlen) {
		txtlen = sptr[0];
		++sptr;
		memcpy(dptr, sptr, txtlen);
		dptr += txtlen;
		sptr += txtlen;
		++datalen;
		datalen += txtlen;
		actuallen += txtlen;
	}
	return actuallen;
}

int 
dns_parse(ins_ans_buf* ins_abuf, unsigned char* bound,
		answerbuf_t* dns_abuf, int dns_abuflen)
{
	int m = ntohs(dns_abuf->header.ancount);
	if (m == 0) {
		return 0;
	}

	ins_abuf->header.aa = dns_abuf->header.aa;
	ins_abuf->header.tc = dns_abuf->header.tc;
	ins_abuf->header.ancount = m;

	unsigned char* dst = ins_abuf->buf + INS_AHEADERSIZE + ins_abuf->header.exaplen;
	unsigned char* ptr = dns_abuf->buf + sizeof(HEADER);
	unsigned char* end = dns_abuf->buf + dns_abuflen;
	int i, n;
	char fullname[INS_PFXMAXSIZE];
	char txtbuf[INS_BUFMAXSIZE];
	n = ntohs(dns_abuf->header.qdcount);
	// first, walk through all the query
	while (n-- > 0) {
		i = dn_expand(dns_abuf->buf, end, ptr, fullname, 256);
		ptr += i;
		if (end - ptr < QFIXEDSZ)
			return -1;
		ptr += QFIXEDSZ;
	}
	// then, extract all the answer
	ins_ans_entry aentry;
	unsigned int rrttl;
	unsigned short rrdlen;
	int aentrylen;

	while (ptr < end && m-- > 0) {
		i = dn_expand(dns_abuf->buf, end, ptr, fullname, 256);
		if (i < 0)
			return -1;
		ptr += i;

		if (end - ptr < 10)
			return -1;

		aentry.type = *(ptr + 1);
		rrttl = *((unsigned int*)(ptr + 4));
		aentry.ttl = ntohl(rrttl);
		rrdlen = *((unsigned short*)(ptr + 8));
		rrdlen = ntohs(rrdlen);

		ptr += 10;

		switch (aentry.type) {
		case INS_T_A: {
			aentry.value = ptr;
			aentry.length = rrdlen;
			break;
		}
		case INS_T_NS:
		case INS_T_CNAME: {
			dn_expand(dns_abuf->buf, end, ptr, fullname, 256);
			aentry.value = fullname;
			aentry.length = strlen(fullname);
			break;
		}
		case INS_T_SOA: 
		case INS_T_TXT: {
			aentry.length = dns_assembletxt(ptr, rrdlen, txtbuf, txtbuf + INS_BUFMAXSIZE);
			aentry.value = txtbuf;
			break;
		}
		case INS_T_CERT:
		case INS_T_RRSIG: {
			aentry.value = ptr;
			aentry.length = rrdlen;
			break;
		}
		default: {
			break;
		}
		}
		
		// for special type
		if (ins_abuf->header.qtype == INS_T_HADMIN && aentry.type == INS_T_TXT) {
			aentry.type = INS_T_HADMIN;
		}
		aentrylen = set_ins_ans_entry(dst, bound, &aentry);
		if (aentrylen < 0) {
			return -1;
		}

		ptr += rrdlen;
		dst += aentrylen;
	}
	return dst - ins_abuf->buf;
}

int
dns_close(res_state state)
{
	res_nclose(state);
	return 0;
}