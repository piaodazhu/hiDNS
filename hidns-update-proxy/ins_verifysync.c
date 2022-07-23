#include "ins_verifysync.h"

int verify_open_udp_socket(const char* validator_ip, unsigned short validator_port)
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
	struct timeval tv;
	tv.tv_sec = 2;
	tv.tv_usec = 0;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
	return fd;
}

int verify_hidns_resolv_ans(hidns_resolv_ans_t *ans)
{
	// prefix relationship check
	verifyreq_buf vrbuf;
	verifyans_buf vabuf;
	int rlen, fd, ret;
	if (ans->querytype == INS_T_CERT) {
		if (ans->rrsetsize != 1) return -1;
		rlen = make_hidns_verify_request_cert(&vrbuf, INS_UDPMAXSIZE, ans);
	}
	else {
		if (ans->signature == NULL) return -1;
		if (ans->signature->signerlen > ans->prefixlen || 
			(memcmp(ans->signature->signerpfx, 
				ans->ansprefix, 
				ans->signature->signerlen) != 0))
		{
			return -2;
		}
		rlen = make_hidns_verify_request_msg(&vrbuf, INS_UDPMAXSIZE, ans);
	}

	if (rlen <= 0) {
		return -3;
	}
	// for debuf
	// printf("[TAG] request message formed. len = %d\n", rlen);
	// FILE *p = fopen("./signature.bin","wb");
	// fwrite(vrbuf.buf, 1, rlen, p);
	// fclose(p);
	//
	fd = verify_open_udp_socket("127.0.0.1", 5551);
	// send message to validator
	ret = send(fd, vrbuf.buf, rlen, 0);
	if (ret != rlen) {
		return 1;
	}
	// printf("[TAG] verify request is sent\n");
	ret = recv(fd, vabuf.buf, INS_UDPMAXSIZE, 0);
	if (ret < VERIFYANS_FIXLEN) {
		return 2;
	}
	// printf("[TAG] verify answer is received! rcode=%d\n", vabuf.header.rcode);
	// parse result
	if (vabuf.header.id != vrbuf.header.id) {
		return 3;
	}
	if (vabuf.header.rcode != VERIFY_ANS_RCODE_OK) {
		return -4;
	}
	return 0;
}

int verify_hidns_x509_cert(const unsigned char* certbuf, int certbuflen, unsigned char certargtype)
{
	// prefix relationship check
	verifyreq_buf vrbuf;
	verifyans_buf vabuf;
	int rlen, fd, ret;
	rlen = make_hidns_verify_request_cert2(&vrbuf, INS_UDPMAXSIZE, certbuf, certbuflen, certargtype);
	if (rlen <= 0) {
		return -3;
	}
	// for debuf
	// printf("[TAG] request message formed. len = %d\n", rlen);
	// FILE *p = fopen("./signature.bin","wb");
	// fwrite(vrbuf.buf, 1, rlen, p);
	// fclose(p);
	//
	fd = verify_open_udp_socket("127.0.0.1", 5551);
	// send message to validator
	ret = send(fd, vrbuf.buf, rlen, 0);
	if (ret != rlen) {
		return 1;
	}
	// printf("[TAG] verify request is sent\n");
	ret = recv(fd, vabuf.buf, INS_UDPMAXSIZE, 0);
	if (ret < VERIFYANS_FIXLEN) {
		return 2;
	}
	// printf("[TAG] verify answer is received! rcode=%d\n", vabuf.header.rcode);
	// parse result
	if (vabuf.header.id != vrbuf.header.id) {
		return 3;
	}
	if (vabuf.header.rcode != VERIFY_ANS_RCODE_OK) {
		return -4;
	}
	return 0;
}

int verify_hidns_nocert_cmd(const unsigned char* tbsbuf, int tbslen, const unsigned char* signerbuf, int signerlen, const unsigned char* sigbuf, int siglen, unsigned char algorithm)
{
	// prefix relationship check
	verifyreq_buf vrbuf;
	verifyans_buf vabuf;
	int rlen, fd, ret;
	rlen = make_hidns_verify_request_msg2(&vrbuf, INS_UDPMAXSIZE, tbsbuf, tbslen, signerbuf, signerlen, sigbuf, siglen, algorithm);
	if (rlen <= 0) {
		return -3;
	}
	// for debuf
	// printf("[TAG] request message formed. len = %d\n", rlen);
	// FILE *p = fopen("./signature.bin","wb");
	// fwrite(vrbuf.buf, 1, rlen, p);
	// fclose(p);
	//
	fd = verify_open_udp_socket("127.0.0.1", 5551);
	// send message to validator
	ret = send(fd, vrbuf.buf, rlen, 0);
	if (ret != rlen) {
		return 1;
	}
	// printf("[TAG] verify request is sent\n");
	ret = recv(fd, vabuf.buf, INS_UDPMAXSIZE, 0);
	if (ret < VERIFYANS_FIXLEN) {
		return 2;
	}
	// printf("[TAG] verify answer is received! rcode=%d\n", vabuf.header.rcode);
	// parse result
	if (vabuf.header.id != vrbuf.header.id) {
		return 3;
	}
	if (vabuf.header.rcode != VERIFY_ANS_RCODE_OK) {
		return -4;
	}
	return 0;
}