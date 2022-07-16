#ifndef HIDNS_VERIFY_SYNC_H
#define HIDNS_VERIFY_SYNC_H

#include "ins_ipsock.h"
#include "verifystruct.h"


int 
verify_open_udp_socket(const char* validator_ip, unsigned short validator_port);

// // verify the answer. return 0 if OK.
int 
verify_hidns_resolv_ans(hidns_resolv_ans_t *ans);

int 
verify_hidns_x509_cert(const unsigned char* certbuf, int certbuflen, unsigned char certargtype);

#endif