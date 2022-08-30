#ifndef HIDNS_SYNC_VERIFY_H
#define HIDNS_SYNC_VERIFY_H

// #include "ipsock.h"
#include "verifystruct.h"


int 
verify_open_udp_socket(const char* validator_ip, unsigned short validator_port);

// // verify the answer. return 0 if OK.
int 
verify_hidns_resolv_ans(hidns_resolv_ans_t *ans);

int 
verify_hidns_x509_cert(const unsigned char* certbuf, int certbuflen, unsigned char certargtype);

int
verify_hidns_nocert_cmd(const unsigned char* tbsbuf, int tbslen, const unsigned char* signerbuf, int signerlen, const unsigned char* sigbuf, int siglen, unsigned char algorithm);

#endif