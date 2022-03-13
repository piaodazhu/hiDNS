#ifndef INS_RESOLV_H
#define INS_RESOLV_H

#include <string.h>
#include <netdb.h>
#include "ins_msgformat.h"
#include "ins_ipsock.h"
#include "ins_localcache.h"

// name and nameserver must be C string ending with 0
struct hostent*
ins_gethostbyname(const char* name, const char* nameserver, 
			int mincomponentcount, int maxcomponentcount);

// prefix and nameserver must be C string ending with 0
struct hostent*
ins_gethostbyprefix(const char* prefix, const char* nameserver);

//-----------------
// name and nameserver must be C string ending with 0
in_addr_t*
ins_getaddrbyname(const char* name, const char* nameserver, 
			int mincomponentcount, int maxcomponentcount);

// name and nameserver must be C string ending with 0
ins_ans_entry*
ins_getnsbyname(const char* name, const char* nameserver, 
			int mincomponentcount, int maxcomponentcount);

// name and nameserver must be C string ending with 0
ins_ans_entry*
ins_gettxtbyname(const char* name, const char* nameserver, 
			int mincomponentcount, int maxcomponentcount);

// name and nameserver must be C string ending with 0
ins_ans_entry*
ins_getsoabyname(const char* name, const char* nameserver, 
			int mincomponentcount, int maxcomponentcount);


in_addr_t*
ins_getaddrbyname2(const char* name, int nlen, const struct sockaddr_in *nameserver, 
			int mincomponentcount, int maxcomponentcount);


ins_ans_entry*
ins_getnsbyname2(const char* name, int nlen, const struct sockaddr_in *nameserver,
			int mincomponentcount, int maxcomponentcount);


ins_ans_entry*
ins_gettxtbyname2(const char* name, int nlen, const struct sockaddr_in *nameserver,
			int mincomponentcount, int maxcomponentcount);


ins_ans_entry*
ins_getsoabyname2(const char* name, int nlen, const struct sockaddr_in *nameserver,
			int mincomponentcount, int maxcomponentcount);

//-----------------

void
ins_free_hostent(struct hostent*);

void
ins_free_aentry(ins_ans_entry*);

void
ins_free_addrlist(in_addr_t*);


// input query packet and output answer packet from nameserver
int
ins_resolv(const struct sockaddr_in *nameserver,
	const ins_qry_buf *qbuf, int qlen, ins_ans_buf *abuf, int *alen);

#endif