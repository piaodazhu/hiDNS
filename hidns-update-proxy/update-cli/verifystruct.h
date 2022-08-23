#ifndef VERIFY_STRUCT_H
#define VERIFY_STRUCT_H
#include <arpa/inet.h>
#include <sys/time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "ins_msgformat.h"
#include "base64.h"

#define HIDNS_ALGO_RSASHA1	5
#define HIDNS_ALGO_RSASHA256	8
#define HIDNS_ALGO_ECDSAP256SHA256	13	
#define HIDNS_ALGO_ECDSAP384SHA384	14
#define HIDNS_ALGO_ED25519	15

#define SIGNATURE_ST_FIXLEN 14
typedef struct hidns_signature_st {
	unsigned short	sigkeytag;
	unsigned char	algorithm;
	unsigned char	signerlen;
	unsigned int	expirtime;
	unsigned int	inceptime;
	unsigned short	sigbuflen;
	unsigned char*	signerpfx;
	unsigned char*	signature;
} hidns_signature_st_t;

typedef struct hidns_resolv_ans
{
	unsigned char	querytype;
	unsigned char	prefixlen;
	unsigned char	rrsetsize;
	unsigned short	tbsbuflen;
	unsigned char*	ansprefix;
	unsigned char**	rrset_lst;
	hidns_signature_st_t*	signature;
}hidns_resolv_ans_t;


// for communication with validator
#define VERIFY_VERSION_0 0
#define VERIFY_PROTOCOL_MSG 0
#define VERIFY_PROTOCOL_CERT 1

#define VERIFY_REQ_OPTIONS_NONE 0
#define VERIFY_REQ_ARGTYPE_TBS 0
#define VERIFY_REQ_ARGTYPE_CERT_DER 2
#define VERIFY_REQ_ARGTYPE_SIGNER_PREFIX 11
#define VERIFY_REQ_ARGTYPE_SIG_ED25519 21
#define VERIFY_REQ_ARGTYPE_SIG_SHA1RSA 22
#define VERIFY_REQ_ARGTYPE_SIG_SHA256RSA 24
#define VERIFY_REQ_ARGTYPE_SIG_SHA256SECP256R1	26
#define VERIFY_REQ_ARGTYPE_SIG_SHA384SECP384R1	27

#define VERIFY_ANS_RCODE_OK 0
#define VERIFY_ANS_RCODE_MSG_MALFORMED 1
#define VERIFY_ANS_RCODE_MSG_INVALIDSIG 2
#define VERIFY_ANS_RCODE_MSG_INVALIDCERT 3
#define VERIFY_ANS_ARGTYPE_CHAINBREAKPOINT 0

typedef struct {
	unsigned 	id: 16;
#if __BYTE_ORDER == __BIG_ENDIAN
	unsigned	version: 4;
	unsigned	protocol: 4;
#endif
#if __BYTE_ORDER == __LITTLE_ENDIAN || __BYTE_ORDER == __PDP_ENDIAN
	unsigned	protocol: 4;
	unsigned	version: 4;
#endif
	unsigned	options: 8;
}VERIFYREQ_HEADER;

#define VERIFYREQ_FIXLEN 4
typedef union {
	VERIFYREQ_HEADER	header;
	unsigned char		buf[INS_UDPMAXSIZE];
} verifyreq_buf;

typedef struct {
	unsigned 	id: 16;
#if __BYTE_ORDER == __BIG_ENDIAN
	unsigned	version: 4;
	unsigned	protocol: 4;
#endif
#if __BYTE_ORDER == __LITTLE_ENDIAN || __BYTE_ORDER == __PDP_ENDIAN
	unsigned	protocol: 4;
	unsigned	version: 4;
#endif
	unsigned	rcode: 8;
}VERIFYANS_HEADER;

#define VERIFYANS_FIXLEN 4
typedef union {
	VERIFYANS_HEADER	header;
	unsigned char		buf[INS_UDPMAXSIZE];
} verifyans_buf;

#define VERIFYARG_FIXLEN 3
typedef struct {
	unsigned char	type;
	unsigned short	length;
	unsigned char	*value;
} verifyarg_tlv;

hidns_resolv_ans_t* 
new_hidns_resolv_ans(ins_ans_buf* anspkt);

void 
free_hidns_resolv_ans(hidns_resolv_ans_t *ans);


hidns_signature_st_t*
new_hidns_signature_st(const char* buf, int len);

void 
free_hidns_signature_st(hidns_signature_st_t *signature);


int
make_hidns_verify_request_msg(verifyreq_buf *reqbuf, int reqbufsize, const hidns_resolv_ans_t *ans);

int
make_hidns_verify_request_msg2(verifyreq_buf *reqbuf, int reqbufsize, const unsigned char* tbsbuf, int tbslen, const unsigned char* signerbuf, int signerlen, const unsigned char* sigbuf, int siglen, unsigned char algorithm);

int
make_hidns_verify_request_cert(verifyreq_buf *reqbuf, int reqbufsize, const hidns_resolv_ans_t *ans);

int
make_hidns_verify_request_cert2(verifyreq_buf *reqbuf, int reqbufsize, const unsigned char* certbuf, int certbuflen, unsigned char certargtype);

#endif