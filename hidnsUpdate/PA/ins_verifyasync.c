#include <fcntl.h>
#include "ins_verifyasync.h"

int 
verify_open_udp_socket_nonblock(const char* validator_ip, unsigned short validator_port)
{
	struct sockaddr_in validator;
	int fd;
	validator.sin_family = AF_INET;
	validator.sin_port = htons(validator_port);
	validator.sin_addr.s_addr = inet_addr(validator_ip);
	if ((fd = socket(validator.sin_family, SOCK_DGRAM, 0)) == -1)
	{
		fprintf(stderr, "Error create udp socket\n");
		return -1;
	}
	if (connect(fd, (struct sockaddr*)&validator, sizeof(struct sockaddr_in)) != 0)
	{
		fprintf(stderr, "Error connect udp socket\n");
		return -1;
	}
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) return flags;
	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) < 0) return -1;
	return fd;
}

int 
verify_hidns_x509_cert_send(int fd, unsigned short req_id, const unsigned char* certbuf, int certbuflen, unsigned char certargtype)
{
	// prefix relationship check
	verifyreq_buf vrbuf;
	int rlen, ret;
	rlen = make_hidns_verify_request_cert2(&vrbuf, INS_UDPMAXSIZE, certbuf, certbuflen, certargtype);
	if (rlen <= 0) {
		return -1;
	}
	vrbuf.header.id = req_id;
	// for debug
	// printf("[TAG] request message formed. len = %d\n", rlen);
	// FILE *p = fopen("./signature.bin","wb");
	// fwrite(vrbuf.buf, 1, rlen, p);
	// fclose(p);
	// send message to validator
	ret = send(fd, vrbuf.buf, rlen, 0);
	if (ret != rlen) {
		return 1;
	}
	return 0;
}

int
verify_hidns_nocert_cmd_send(int fd, unsigned short req_id, const unsigned char* tbsbuf, int tbslen, const unsigned char* signerbuf, int signerlen, const unsigned char* sigbuf, int siglen, unsigned char algorithm)
{
	// prefix relationship check
	verifyreq_buf vrbuf;
	int rlen, ret;
	rlen = make_hidns_verify_request_msg2(&vrbuf, INS_UDPMAXSIZE, tbsbuf, tbslen, signerbuf, signerlen, sigbuf, siglen, algorithm);
	if (rlen <= 0) {
		return -1;
	}
	vrbuf.header.id = req_id;
	// for debuf
	// printf("[TAG] request message formed. len = %d\n", rlen);
	// FILE *p = fopen("./signature.bin","wb");
	// fwrite(vrbuf.buf, 1, rlen, p);
	// fclose(p);
	// send message to validator
	ret = send(fd, vrbuf.buf, rlen, 0);
	if (ret != rlen) {
		return 1;
	}
	return 0;
}

int 
verify_hidns_getresult(int fd, unsigned short *reply_id)
{
	verifyans_buf vabuf;
	int ret;
	ret = recv(fd, vabuf.buf, INS_UDPMAXSIZE, 0);
	if (ret < VERIFYANS_FIXLEN) {
		return 2;
	}
	// printf("[TAG] verify answer is received! rcode=%d\n", vabuf.header.rcode);
	// parse result
	*reply_id = vabuf.header.id;
	// return 0;
	return vabuf.header.rcode;
}
