#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "updatemsgtools.h"
#include "updatemsgfmt.h"

userkeypair *keypairhead;
int main()
{
	// test_sign("helloworld", strlen("helloworld"), "./curveprivate.key");
	load_userkeypair("private.key", "cert.pem", 0, HIDNS_ALGO_ECDSAP384SHA384, &keypairhead);
	if (keypairhead == NULL) {
		perror("Can't load keypair.");
		return 1;
	}

	hidns_update_command *cmd = updatemsg_new_command();
	cmd->opcode = COMMAND_OPCODE_ADDRR;
	cmd->rrtype = COMMAND_RRTYPE_TXT;
	cmd->rrprefixlen = strlen("/icn/bit/user1/");
	cmd->rrprefixbuf = "/icn/bit/user1/";
	cmd->rrvaluelen = strlen("helloworld");
	cmd->rrvaluebuf = "helloworld";
	cmd->rrttl = 86400;
	hidns_update_signature *sig = sign_rawcommand(cmd, 0, keypairhead);
	hidns_update_certificate *cert = updatemsg_new_certificate();
	cert->type = CERTIFICATE_TYPE_X509_DER;
	cert->length = get_userkeypair(keypairhead, 0)->certlen;
	cert->valbuf = get_userkeypair(keypairhead, 0)->certbuf;

	hidns_update_msg *msg = updatemsg_new_message();

	updatemsg_append_command(msg, cmd);
	updatemsg_append_signature(msg, sig);
	updatemsg_append_certificate(msg, cert);

	// FILE *f = fopen("dump.bin", "wb");
	// fwrite(msg->rawbuf, 1, msg->rawbuflen, f);
	// fclose(f);

	// FILE *f = fopen("cert.der", "wb");
	// fwrite(msg->cert.valbuf, 1, msg->cert.length, f);
	// fclose(f);


	int fd = socket(AF_INET, SOCK_STREAM, 0);
	socklen_t socklen;
	struct sockaddr_in server;
	struct sockaddr_in addr;
	server.sin_addr.s_addr = inet_addr("127.0.0.1");
	server.sin_port = htons(1038);
	server.sin_family = AF_INET;

	hidns_update_msg reply;
	int len;

	if (connect(fd, (struct sockaddr*)&server, sizeof(server)) != 0) {
		perror("connect");
		return 1;
	}
	send(fd, msg->rawbuf, msg->rawbuflen, 0);
	int rlen = recv(fd, (void*)&reply.len_n, sizeof(reply.len_n), 0);
	if (rlen != sizeof(reply.len_n)) {
		perror("recv_reply_len");
		return 1;
	}
	len = ntohs(reply.len_n);
	rlen = recv(fd, (void*)&reply.buf, len, 0);
	if (rlen != len) {
		perror("recv_reply_message");
		return 1;
	}
	close(fd);
	if (updatemsg_parse(&reply) != 0) {
		perror("updatemsg_parse");
	}
	printf("reply rcode=%u\n", reply.rcode);

	return 0;
}
