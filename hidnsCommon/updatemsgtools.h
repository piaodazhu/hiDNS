#ifndef UPDATEMSGTOOLS_H
#define UPDATEMSGTOOLS_H

#include <stdio.h>
#include <string.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "updatemsgfmt.h"

typedef struct userkeypair userkeypair;
struct userkeypair{
	unsigned short	keytag;
	unsigned char	algorithm;
	unsigned char	subjectlen;
	unsigned char*	subjectpfx;
	EC_KEY*		privatekey;
	unsigned short	certlen;
	unsigned char*	certbuf;
	userkeypair*	next;
};

int load_userkeypair(const char* keyfilename, const char* certfilename,
	unsigned short keytag, unsigned char algorithm, userkeypair** userkeylist);

userkeypair* get_userkeypair(userkeypair* userkeylist, unsigned short keytag);

hidns_update_signature* sign_rawcommand(hidns_update_command *cmd, 
	unsigned short keytag, userkeypair* userkeylist);

#define CHECK_MSG_OK	0
#define CHECK_MSG_INCOMPLETE	-1
#define CHECK_MSG_OUTOFDATE	-2
#define CHECK_MSG_INVALIDSIG	-3
#define CHECK_MSG_INVALIDPFX	-4
#define CHECK_MSG_INVALIDCERT	-5
#define CHECK_MSG_SERVERFAIL	-6
#define CHECK_MSG_CERTABSENT	1
#define CHECK_MSG_UNSUPTCERT	2

// return 0 if checking passed, return > 0 if certificate not in the message, return < 0 if checking failed
int check_updatemsg_request(hidns_update_msg *msg);
// return 0 if checking passed, return > 0 if certificate not in the message, return < 0 if checking failed
int check_updatemsg_reply(hidns_update_msg *msg);
// return 1 if match, return 0 if not match
int check_updatemsg_ismatch(hidns_update_msg *request, hidns_update_msg *reply);



#endif