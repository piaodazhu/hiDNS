#ifndef DNS_UTILS_H
#define DNS_UTILS_H

#include <netinet/in.h>
#include "loadconf.h"

typedef union answerbuf
{
	HEADER header;
	unsigned char buf[PACKETSZ];

}answerbuf_t;

int 
dns_init(ins_qry_buf* ins_qbuf, res_state state, struct sockaddr_in nameserver);

int 
dns_resolve(ins_qry_buf* ins_qbuf, res_state state, unsigned char* domainname,
		answerbuf_t* dns_abuf, int* dns_abuflen);

int 
dns_parse(ins_ans_buf* ins_abuf, unsigned char* bound,
		answerbuf_t* dns_abuf, int dns_abuflen);

int
dns_close(res_state state);


#endif