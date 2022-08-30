#include "verifystruct.h"

hidns_resolv_ans_t* 
new_hidns_resolv_ans(ins_ans_buf* anspkt)
{
	if (anspkt == NULL || anspkt->header.ancount == 0) 
		return NULL;
	
	hidns_resolv_ans_t *ans = (hidns_resolv_ans_t*) malloc (sizeof(hidns_resolv_ans_t));
	ans->querytype = anspkt->header.qtype;
	ans->rrsetsize = 0;
	ans->tbsbuflen = 0;
	ans->prefixlen = anspkt->header.exaplen;
	ans->ansprefix = malloc(ans->prefixlen);
	memcpy(ans->ansprefix, anspkt->buf + INS_AHEADERSIZE, ans->prefixlen);
	
	int ancount = anspkt->header.ancount;
	int i, len;
	unsigned char *ptr, *bound;
	ins_ans_entry aentry;
	unsigned char** rlistptr;

	ans->rrset_lst = (unsigned char**) malloc(ancount * sizeof(unsigned char*));
	rlistptr = ans->rrset_lst;

	ptr = anspkt->buf + INS_AHEADERSIZE + anspkt->header.exaplen;
	bound = anspkt->buf + INS_UDPMAXSIZE;
	for (i = 0; i < ancount; i++) {
		len = get_ins_ans_entry(ptr, bound, &aentry);
		if (len < 0) {
			free_hidns_resolv_ans(ans);
			return NULL;
		}
		else if (aentry.type == anspkt->header.qtype) {
			// copy the answer entry length and buffer to a list item
			*rlistptr = malloc(len + 2);
			memcpy(*rlistptr, &len, 2);
			memcpy(*rlistptr + 2, ptr, len);
			// printf("len = %d, value = %.*s\n", len, aentry.length, aentry.value);
			++rlistptr;
			++ans->rrsetsize;
			ans->tbsbuflen += (len + 2);
		}
		else if (aentry.type == INS_T_HSIG) {
			// extract rrsig
			printf("[TAG] find hsig in the answer\n");
			ans->signature = new_hidns_signature_st((const char*)aentry.value, aentry.length);
		}
		else {
			// wrong condition
			free_hidns_resolv_ans(ans);
			return NULL;
		}
		ptr += len;
	}
	ans->tbsbuflen += ans->prefixlen;

	if (ans->rrsetsize == 0) {
		free_hidns_resolv_ans(ans);
		return NULL;
	}
	return ans;
}

void 
free_hidns_resolv_ans(hidns_resolv_ans_t *ans) {
	if (ans->prefixlen != 0) free(ans->ansprefix);
	if (ans->signature != 0) free_hidns_signature_st(ans->signature);
	if (ans->rrsetsize != 0) {
		int i, len = ans->rrsetsize;
		for (i = 0; i < len; i++) {
			free(ans->rrset_lst[i]);
		}
		free(ans->rrset_lst);
	}
	free(ans);
	return;
}

hidns_signature_st_t*
new_hidns_signature_st(const char* buf, int len)
{
	unsigned char *decode_out;
	int decode_len;
	decode_out = malloc(BASE64_DECODE_OUT_SIZE(len));
	decode_len = base64_decode(buf, len, decode_out);
	if (decode_len < SIGNATURE_ST_FIXLEN) {
		free(decode_out);
		return NULL;
	}
	hidns_signature_st_t* signature = (hidns_signature_st_t*) malloc(sizeof(hidns_signature_st_t));

	unsigned char* ptr = decode_out;
	// unsigned char* bound = decode_out + decode_len;

	signature->sigkeytag = ntohs(*(unsigned short*)ptr);
	ptr += 2;
	signature->algorithm = *ptr;
	ptr += 1;
	signature->expirtime = ntohl(*(unsigned int*)ptr);
	ptr += 4;
	signature->inceptime = ntohl(*(unsigned int*)ptr);
	ptr += 4;
	signature->signerlen = *ptr;
	ptr += 1;
	signature->sigbuflen = ntohs(*(unsigned short*)ptr);
	ptr += 2;
	if (SIGNATURE_ST_FIXLEN + signature->signerlen + signature->sigbuflen != decode_len) {
		printf("[TAG] signature load error\n");
		free(signature);
		free(decode_out);
		return NULL;
	}
	signature->signerpfx = malloc(signature->signerlen);
	signature->signature = malloc(signature->sigbuflen);
	memcpy(signature->signerpfx, ptr, signature->signerlen);
	ptr += signature->signerlen;
	memcpy(signature->signature, ptr, signature->sigbuflen);
	free(decode_out);
	printf("[TAG] signature load success\n");
	return signature;
}

void 
free_hidns_signature_st(hidns_signature_st_t *signature) {
	if (signature->signerlen != 0) free(signature->signerpfx);
	if (signature->sigbuflen != 0) free(signature->signature);
	free(signature);
	return;
}

int
make_hidns_verify_request_msg(verifyreq_buf *reqbuf, int reqbufsize, const hidns_resolv_ans_t *ans)
{
	// check bound?
	unsigned short arglen1, arglen2, arglen3;
	unsigned short arglen1_n, arglen2_n, arglen3_n;
	arglen1 = ans->signature->signerlen;
	arglen2 = ans->signature->sigbuflen;
	arglen3 = ans->tbsbuflen;
// printf("[TAG] 1 arglen1 = %d, arglen2 = %d, arglen3 = %d\n", arglen1, arglen2, arglen3);
	if (reqbufsize < VERIFYREQ_FIXLEN + 3 * VERIFYARG_FIXLEN + arglen1 + arglen2 + arglen3)
		return 0;
	
	struct timeval tv;
	gettimeofday(&tv, NULL);
	reqbuf->header.id = tv.tv_usec & 0xffff;
	reqbuf->header.version = VERIFY_VERSION_0;
	reqbuf->header.protocol = VERIFY_PROTOCOL_MSG;
	reqbuf->header.options = VERIFY_REQ_OPTIONS_NONE;
	
	unsigned char* ptr = reqbuf->buf + VERIFYREQ_FIXLEN;
	
	// 1. add signer prefix argument
	
	*ptr = VERIFY_REQ_ARGTYPE_SIGNER_PREFIX;
	ptr++;
	arglen1_n = htons(arglen1);
	memcpy(ptr, &arglen1_n, 2);
	ptr += 2;
	memcpy(ptr, ans->signature->signerpfx, arglen1);
	ptr += arglen1;
// printf("[TAG] 2\n");
	// 2. add signature prefix argument
	
	switch (ans->signature->algorithm) {
	case HIDNS_ALGO_RSASHA1: 
		*ptr = VERIFY_REQ_ARGTYPE_SIG_SHA1RSA;
		break;
	case HIDNS_ALGO_RSASHA256: 
		*ptr = VERIFY_REQ_ARGTYPE_SIG_SHA256RSA;
		break;
	case HIDNS_ALGO_ECDSAP256SHA256: 
		*ptr = VERIFY_REQ_ARGTYPE_SIG_SHA256SECP256R1;
		break;
	case HIDNS_ALGO_ECDSAP384SHA384: 
		*ptr = VERIFY_REQ_ARGTYPE_SIG_SHA384SECP384R1;
		break;
	case HIDNS_ALGO_ED25519: 
		*ptr = VERIFY_REQ_ARGTYPE_SIG_ED25519;
		break;
	default:
		*ptr = 0; 
		break;
	}
	ptr++;
	arglen2_n = htons(arglen2);
	memcpy(ptr, &arglen2_n, 2);
	ptr += 2;
	memcpy(ptr, ans->signature->signature, arglen2);
	ptr += arglen2;
// printf("[TAG] 3\n");
	// 3. add to-be-signed message argument
	// the tbs is: rrset_list item in ascending order + ansprefix
	
	*ptr = VERIFY_REQ_ARGTYPE_TBS;
	ptr++;
	arglen3_n = htons(arglen3);
	memcpy(ptr, &arglen3_n, 2);
	ptr += 2;
	// sort and copy.
	unsigned char** rrptr = (unsigned char**)malloc(ans->rrsetsize * sizeof(unsigned char*));
	unsigned short* rrlen = (unsigned short*)malloc(ans->rrsetsize * sizeof(unsigned short));
	unsigned char* maxrrptr;
	unsigned short maxrrlen;
	int cmp, i, j, maxrridx;
	for (i = 0; i < ans->rrsetsize; i++) {
		rrptr[i] = ans->rrset_lst[i] + 2;
		rrlen[i] = *(unsigned short*)ans->rrset_lst[i];
	}
	for (i = 0; i < ans->rrsetsize; i++) {
		maxrrptr = rrptr[i];
		maxrrlen = rrlen[i];
		maxrridx = i;
		for (j = i + 1; j < ans->rrsetsize; j++) {
			cmp = memcmp(maxrrptr, rrptr[j], MIN(maxrrlen, rrlen[j]));
			if (cmp > 0 || (cmp == 0 && maxrrlen > rrlen[j])) {
				maxrrptr = rrptr[j];
				maxrrlen = rrlen[j];
				maxrridx = j;
			}
		}
		memcpy(ptr, maxrrptr, maxrrlen);
		ptr += maxrrlen;
		rrptr[maxrridx] = rrptr[i];
		rrlen[maxrridx] = rrlen[i];
	}

	memcpy(ptr, ans->ansprefix, ans->prefixlen);
	ptr += ans->prefixlen;
// printf("[TAG] 4\n");
	return ptr - reqbuf->buf; 
}

int
make_hidns_verify_request_msg2(verifyreq_buf *reqbuf, int reqbufsize, const unsigned char* tbsbuf, int tbslen, const unsigned char* signerbuf, int signerlen, const unsigned char* sigbuf, int siglen, unsigned char algorithm)
{
	if (reqbufsize < VERIFYREQ_FIXLEN + 3 * VERIFYARG_FIXLEN + tbslen + signerlen + siglen)
		return 0;
	
	struct timeval tv;
	unsigned short arglen1 = tbslen, arglen2 = signerlen, arglen3 = siglen;
	unsigned short arglen1_n, arglen2_n, arglen3_n;
	gettimeofday(&tv, NULL);
	reqbuf->header.id = tv.tv_usec & 0xffff;
	reqbuf->header.version = VERIFY_VERSION_0;
	reqbuf->header.protocol = VERIFY_PROTOCOL_MSG;
	reqbuf->header.options = VERIFY_REQ_OPTIONS_NONE;
	
	unsigned char* ptr = reqbuf->buf + VERIFYREQ_FIXLEN;
	
	// 1. add tbs argument
	*ptr = VERIFY_REQ_ARGTYPE_TBS;
	ptr++;
	arglen1_n = htons(arglen1);
	memcpy(ptr, &arglen1_n, 2);
	ptr += 2;
	memcpy(ptr, tbsbuf, arglen1);
	ptr += arglen1;

	// 2. add signer argument
	*ptr = VERIFY_REQ_ARGTYPE_SIGNER_PREFIX;
	ptr++;
	arglen2_n = htons(arglen2);
	memcpy(ptr, &arglen2_n, 2);
	ptr += 2;
	memcpy(ptr, signerbuf, arglen2);
	ptr += arglen2;

	// 3. add signature
	switch (algorithm) {
	case HIDNS_ALGO_RSASHA1: 
		*ptr = VERIFY_REQ_ARGTYPE_SIG_SHA1RSA;
		break;
	case HIDNS_ALGO_RSASHA256: 
		*ptr = VERIFY_REQ_ARGTYPE_SIG_SHA256RSA;
		break;
	case HIDNS_ALGO_ECDSAP256SHA256: 
		*ptr = VERIFY_REQ_ARGTYPE_SIG_SHA256SECP256R1;
		break;
	case HIDNS_ALGO_ECDSAP384SHA384: 
		*ptr = VERIFY_REQ_ARGTYPE_SIG_SHA384SECP384R1;
		break;
	case HIDNS_ALGO_ED25519: 
		*ptr = VERIFY_REQ_ARGTYPE_SIG_ED25519;
		break;
	default:
		*ptr = 0; 
		break;
	}
	ptr++;
	arglen3_n = htons(arglen3);
	memcpy(ptr, &arglen3_n, 2);
	ptr += 2;
	memcpy(ptr, sigbuf, arglen3);
	ptr += arglen3;
	
	return ptr - reqbuf->buf; 
}

int
make_hidns_verify_request_cert(verifyreq_buf *reqbuf, int reqbufsize, const hidns_resolv_ans_t *ans)
{
	// check bound?
	unsigned short arglen;
	unsigned short arglen_n;
	// parse cert
	unsigned char *entryptr = ans->rrset_lst[0] + 2;
	unsigned int entrylen = *(unsigned short*)ans->rrset_lst[0];
	unsigned char *entrybound = entryptr + entrylen;
	ins_ans_entry entry;
	if ((get_ins_ans_entry(entryptr, entrybound, &entry) != entrylen))
		return 0;
// printf("[TAG] 1 arglen1 = %d, arglen2 = %d, arglen3 = %d\n", arglen1, arglen2, arglen3);
	arglen = entry.length - 5;
	if (reqbufsize < VERIFYREQ_FIXLEN + VERIFYARG_FIXLEN + arglen)
		return 0;
	
	struct timeval tv;
	gettimeofday(&tv, NULL);
	reqbuf->header.id = tv.tv_usec & 0xffff;
	reqbuf->header.version = VERIFY_VERSION_0;
	reqbuf->header.protocol = VERIFY_PROTOCOL_CERT;
	reqbuf->header.options = VERIFY_REQ_OPTIONS_NONE;
	
	unsigned char* ptr = reqbuf->buf + VERIFYREQ_FIXLEN;
	
	// 1. add certificate argument
	*ptr = VERIFY_REQ_ARGTYPE_CERT_DER;
	ptr++;
	arglen_n = htons(arglen);
	memcpy(ptr, &arglen_n, 2);
	ptr += 2;
	memcpy(ptr, entry.value + 5, arglen);
	ptr += arglen;
// printf("[TAG] 2\n");
	return ptr - reqbuf->buf; 
}

int
make_hidns_verify_request_cert2(verifyreq_buf *reqbuf, int reqbufsize, const unsigned char* certbuf, int certbuflen, unsigned char certargtype)
{
	if (reqbufsize < VERIFYREQ_FIXLEN + VERIFYARG_FIXLEN + certbuflen)
		return 0;
	
	struct timeval tv;
	unsigned short arglen = certbuflen;
	unsigned short arglen_n;
	gettimeofday(&tv, NULL);
	reqbuf->header.id = tv.tv_usec & 0xffff;
	reqbuf->header.version = VERIFY_VERSION_0;
	reqbuf->header.protocol = VERIFY_PROTOCOL_CERT;
	reqbuf->header.options = VERIFY_REQ_OPTIONS_NONE;
	
	unsigned char* ptr = reqbuf->buf + VERIFYREQ_FIXLEN;
	
	// 1. add certificate argument
	*ptr = certargtype;
	ptr++;
	arglen_n = htons(arglen);
	memcpy(ptr, &arglen_n, 2);
	ptr += 2;
	memcpy(ptr, certbuf, arglen);
	ptr += arglen;
	return ptr - reqbuf->buf; 
}
