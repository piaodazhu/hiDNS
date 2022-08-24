#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "updatemsgtools.h"
#include "updatemsgfmt.h"
#include "ins_verifysync.h"

#define PAPORT		1038
#define PAPORT_SEC	1039
#define TESTPORT	4433
#define PAIPADDR	"127.0.0.1"

userkeypair *keypairhead;
void init_ssl()
{
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
}

int verify_cb(int n, X509_STORE_CTX *store)
{
	// here add verify
	X509 *cert = X509_STORE_CTX_get_current_cert(store);
	unsigned char certbuf[2048];
	unsigned char *bufptr = certbuf;
	int certbuflen, ret;
	certbuflen = i2d_X509(cert, &bufptr);

	ret = verify_hidns_x509_cert(certbuf, certbuflen, VERIFY_REQ_ARGTYPE_CERT_DER);
	if (ret == 0) {
		printf("certificate verify ok\n");
		return 1;
	}
	printf("certificate verify failed\n");
	return 0;
	// return 1;
}

int main()
{
	init_ssl();
	SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
	// SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, "private.key", SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb);
	SSL *ssl = SSL_new(ctx);
	load_userkeypair("private.key", "cert.pem", 0, HIDNS_ALGO_ECDSAP384SHA384, &keypairhead);
	if (keypairhead == NULL)
	{
		perror("Can't load keypair.");
		return 1;
	}

	hidns_update_command *cmd = updatemsg_new_command();
	cmd->opcode = COMMAND_OPCODE_ADDRR;
	cmd->rrtype = COMMAND_RRTYPE_TXT;
	cmd->rrprefixlen = strlen("/icn/bit/user2/");
	cmd->rrprefixbuf = "/icn/bit/user2/";
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


	int fd = socket(AF_INET, SOCK_STREAM, 0);
	int ret;
	socklen_t socklen;
	struct sockaddr_in server;
	struct sockaddr_in addr;
	server.sin_addr.s_addr = inet_addr(PAIPADDR);
	server.sin_port = htons(PAPORT_SEC);
	server.sin_family = AF_INET;

	hidns_update_msg reply;
	int len;

	if (connect(fd, (struct sockaddr *)&server, sizeof(server)) != 0)
	{
		perror("connect");
		return 1;
	}
	SSL_set_fd(ssl, fd);
	if ((ret = SSL_connect(ssl)) != 1)
	{
		fprintf(stderr, "SSL connect failed! ret %d\n", ret);
		ERR_print_errors_fp(stderr);
		fprintf(stderr, "SSL connect failed! ret %d errcode:%d\n", ret, SSL_get_error(ssl, ret));
		return -1;
	}
	// X509 *peercert = SSL_get_peer_certificate(ssl);
	// X509_NAME *issuer = X509_get_issuer_name(peercert);
	// int cnt = X509_NAME_entry_count(issuer);
	// printf("Tag0: %d\n", cnt);
	// int i;
	// unsigned char *p;
	// size_t nlen;
	// for (i = 0; i < cnt; i++)
	// {
	// 	ASN1_STRING *s = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(issuer, i));
	// 	printf("-->Tag1: %s\n", ASN1_STRING_get0_data(s));
	// }
	// // unsigned char *p;
	// // size_t nlen;
	// // X509_NAME_get0_der(issuer, &p, &nlen);
	// // printf("Tag1: %u\n", nlen);

	SSL_write(ssl, msg->rawbuf, msg->rawbuflen);
	printf("Tag2\n");
	int rlen = SSL_read(ssl, (void *)&reply.len_n, sizeof(reply.len_n));
	if (rlen != sizeof(reply.len_n))
	{
		perror("recv_reply_len");
		return 1;
	}
	printf("Tag3\n");
	len = ntohs(reply.len_n);
	rlen = SSL_read(ssl, (void *)&reply.buf, len);
	if (rlen != len)
	{
		perror("recv_reply_message");
		return 1;
	}
	printf("Tag4\n");
	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	close(fd);

	if (updatemsg_parse(&reply) != 0)
	{
		perror("updatemsg_parse");
	}
	printf("reply rcode=%u\n", reply.rcode);

	return 0;
}
