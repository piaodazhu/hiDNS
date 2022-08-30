#ifndef INS_ASYNC_VERIFY_H
#define INS_ASYNC_VERIFY_H

#include "verifystruct.h"

int 
verify_open_udp_socket_nonblock(const char* validator_ip, unsigned short validator_port);

int 
verify_hidns_x509_cert_send(int fd, unsigned short req_id, const unsigned char* certbuf, int certbuflen, unsigned char certargtype);

int
verify_hidns_nocert_cmd_send(int fd, unsigned short req_id, const unsigned char* tbsbuf, int tbslen, const unsigned char* signerbuf, int signerlen, const unsigned char* sigbuf, int siglen, unsigned char algorithm);

int 
verify_hidns_getresult(int fd, unsigned short *reply_id);

#endif