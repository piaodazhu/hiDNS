#ifndef UPDATEMSGFMT_H
#define UPDATEMSGFMT_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

// global defination
#define UPDATE_MSG_MAXBUFSIZE	4096
#define UNDEFINED_TYPEID	0x0

// A. prefix resource record update command structure

typedef struct {
	unsigned int	id;
	unsigned int	ts;
	unsigned char	opcode;
	unsigned char	rrtype;
	unsigned char	rrprefixlen;
	unsigned char	reserved;
	unsigned int	rrttl;
	unsigned short	rrvaluelen;
	unsigned char*	rrprefixbuf;
	unsigned char*	rrvaluebuf;
} hidns_update_command;

#define COMMAND_FIXLEN	18
#define COMMAND_TYPEID	0x1

#define COMMAND_OPCODE_NON	0
#define COMMAND_OPCODE_ADDRR	1
#define COMMAND_OPCODE_DELRR	2
#define COMMAND_OPCODE_GETRRS	3
#define COMMAND_OPCODE_PUTSIG	4

#define COMMAND_RRTYPE_A	T_A
#define COMMAND_RRTYPE_NS	T_NS
#define COMMAND_RRTYPE_TXT	T_TXT
#define COMMAND_RRTYPE_CERT	T_CERT
#define COMMAND_RRTYPE_HSIG	222
#define COMMAND_RRTYPE_A_TBF	223

int command_parse(hidns_update_command* cmd, unsigned char *ptr, int len);


// B. type-length-value common structure
//    certificate and additional value is also in form of tlv
typedef struct {
	unsigned	type: 8;
	unsigned	length: 16;
	unsigned char*	valbuf;
} hidns_update_tlv, hidns_update_certificate, hidns_update_addition;

#define TLV_FIXLEN			3
#define COMMONTLV_TYPEID		0x2
#define COMMONTLV_TYPE_NON		0x0
#define COMMONTLV_TYPE_TBS		0x1

#define CERTIFICATE_TYPEID		0x3
#define CERTIFICATE_TYPE_X509_DER	0x0
#define CERTIFICATE_TYPE_X509_PEM	0x1
#define CERTIFICATE_TYPE_X509_DERB64	0x2

#define ADDITION_TYPEID			0x4
#define ADDITION_TYPE_A			T_A

int commontlv_parse(hidns_update_tlv* tlv, unsigned char *ptr, int len);


// C. signature structure of prefix RR update command
typedef struct {
	unsigned short	sigkeytag;
	unsigned char	algorithm;
	unsigned char	signerlen;
	unsigned int	expirtime;
	unsigned int	inceptime;
	unsigned short	sigbuflen;
	unsigned char*	signerpfx;
	unsigned char*	signature;
} hidns_update_signature;

#define SIGNATURE_FIXLEN	14
#define SIGNATURE_TYPEID	0x5

#define HIDNS_ALGO_RSASHA1	5
#define HIDNS_ALGO_RSASHA256	8
#define HIDNS_ALGO_ED25519	15

int signature_parse(hidns_update_signature* sig, unsigned char *ptr, int len);


// B. rcode
typedef char hidns_update_rcode;

#define RCODE_FIXLEN	1
#define RCODE_TYPEID	0x6

#define RCODE_OK	0x0
#define RCODE_INVALID_PACKET	0x10
#define RCODE_UNAUTH_PREFIX	0x11
#define RCODE_SERVER_ERROR	0x20

// E. the update message structure. certificate can be NULL if the prefix certificate could be fetch from hidns server.
struct hidns_update_msg {
	hidns_update_command		cmd;
	hidns_update_signature		sig;
	hidns_update_certificate	cert;
	hidns_update_addition		addval;
	hidns_update_tlv		args;
	hidns_update_rcode		rcode;
	unsigned short			rawbuflen;
	unsigned char			_membermap;
	unsigned short			_tbslen;
	unsigned char*			_tbsptr;
	union
	{
		unsigned char	rawbuf[UPDATE_MSG_MAXBUFSIZE];
		struct
		{
			unsigned short	len_n;
			unsigned char	buf[UPDATE_MSG_MAXBUFSIZE - 2];
		};
	};
};
typedef struct hidns_update_msg hidns_update_msg;

#define MSG_MEMBER_MAP_CMD	0b1
#define MSG_MEMBER_MAP_SIG	0b10
#define MSG_MEMBER_MAP_CERT	0b100
#define MSG_MEMBER_MAP_ADD	0b1000
#define MSG_MEMBER_MAP_ARGS	0b10000
#define MSG_MEMBER_MAP_RCODE	0b100000

void updatemsg_init(hidns_update_msg* msg);
int updatemsg_parse(hidns_update_msg* msg);
int updatemsg_append_command(hidns_update_msg* msg, hidns_update_command* cmd);
int updatemsg_append_signature(hidns_update_msg* msg, hidns_update_signature* sig);
int updatemsg_append_addition(hidns_update_msg* msg, hidns_update_addition* addv);
int updatemsg_append_certificate(hidns_update_msg* msg, hidns_update_certificate* cert);
int updatemsg_set_rcode(hidns_update_msg* msg, hidns_update_rcode rcode);
// new value
hidns_update_msg* updatemsg_new_message();
hidns_update_command* updatemsg_new_command();
hidns_update_signature* updatemsg_new_signature();
hidns_update_addition* updatemsg_new_addition();
hidns_update_certificate* updatemsg_new_certificate();
// free value
void updatemsg_free_message(hidns_update_msg* msg);
void updatemsg_free_command(hidns_update_command* cmd);
void updatemsg_free_signature(hidns_update_signature* sig);
void updatemsg_free_addition(hidns_update_addition* add);
void updatemsg_free_certificate(hidns_update_certificate* cert);

#endif
