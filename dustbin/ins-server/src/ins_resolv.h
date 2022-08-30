#ifndef INS_RESOLV_H
#define INS_RESOLV_H

#include <string.h>
#include <netdb.h>
#include "ins_msgformat.h"
#include "ins_ipsock.h"
#include "ins_cache.h"
#include "ins_verifysync.h"
#include "verifystruct.h"

// #define INS_UNIX_SOCK
#define INS_UDP_SOCK
#ifdef INS_UNIX_SOCK
#include <sys/un.h>
#endif	

// These are resolver flags. they can be combined with 'or (|)'
// Use Datagram TLS to protect hiDNS resolution (Need run DTLS proxy service).
#define RESOLV_FLAG_OVER_DTLS	0x1
// If the answer is checked by recursive server and AD bit is set, trust this answer anyway. If AD bit is not set, local verify will be executed (Need run validator service).
#define RESOLV_FLAG_TRUST_AD	0x10
// This will set CD bit in query and Always execute local verify (Need run validator service).
#define RESOLV_FLAG_MUST_VERIFY	0x100
// Cache valid answer. If verify disabled, cache any answer. (Need run cache service)
#define RESOLV_FLAG_AUTO_CACHE	0x1000
// Default policy: dtls, local verify, auto cache. 
#define RESOLV_FLAG_DEFAULT	0x1011

// name and nameserver must be C string ending with 0
struct hostent*
ins_gethostbyname(const char* name, const char* nameserver, 
			int mincomponentcount, int maxcomponentcount);

// prefix and nameserver must be C string ending with 0
struct hostent*
ins_gethostbyprefix(const char* prefix, const char* nameserver);

//-----------------
// name and nameserver must be C string ending with 0
in_addr_t**
ins_getaddrbyname(const char* name, const char* nameserver, 
			int mincomponentcount, int maxcomponentcount);

// name and nameserver must be C string ending with 0
char**
ins_getnsbyname(const char* name, const char* nameserver, 
			int mincomponentcount, int maxcomponentcount);

// name and nameserver must be C string ending with 0
char**
ins_gettxtbyname(const char* name, const char* nameserver, 
			int mincomponentcount, int maxcomponentcount);


// name and nameserver must be C string ending with 0
struct sockaddr**
ins_getadminbyname(const char* name, const char* nameserver, 
			int mincomponentcount, int maxcomponentcount);

in_addr_t**
ins_getaddrbyname2(const char* name, int nlen, const struct sockaddr_in *nameserver, 
			int mincomponentcount, int maxcomponentcount);


char**
ins_getnsbyname2(const char* name, int nlen, const struct sockaddr_in *nameserver,
			int mincomponentcount, int maxcomponentcount);


char**
ins_gettxtbyname2(const char* name, int nlen, const struct sockaddr_in *nameserver,
			int mincomponentcount, int maxcomponentcount);

struct sockaddr**
ins_getadminbyname2(const char* name, int nlen, const struct sockaddr_in *nameserver, 
			int mincomponentcount, int maxcomponentcount);

//-----------------

int  insprefix_countcomponents(const char* prefix, int plen);
void ins_free_hostent(struct hostent*);
void ins_free_aentry(ins_ans_entry*);
void ins_free_addrlist(in_addr_t**);
void ins_free_sockaddrlist(struct sockaddr**);
void ins_free_buflist(char**);

// input query packet and output answer packet from nameserver
int
ins_resolv(const struct sockaddr_in *nameserver,
	const ins_qry_buf *qbuf, int qlen, ins_ans_buf *abuf, int *alen);


hidns_resolv_ans_t*
ins_resolv2(const char* name, int nlen, const struct sockaddr_in *nameserver,
			int mincomponentcount, int maxcomponentcount, 
			int qtype, int flags);

#endif