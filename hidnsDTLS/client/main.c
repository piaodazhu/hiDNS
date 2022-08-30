#include "session.h"
#include "resolvmsgfmt.h"
#include "syncverify.h"

#define BUFFER_SIZE          	4096
#define COOKIE_SECRET_LENGTH 	16
#define SESSION_TIMEOUT 	100	//second
#define HIDNS_TIMEOUT		1

#define DTLS_SERVER_LPORT	5554
#define DTLS_CLIENT_LPORT	5556

int verbose = 1;
union mysockaddr hidns_local_addr;
int hidns_fd;
session *session_list = NULL;
int client_count = 0;
int sessioncount = -1;
char buf[BUFFER_SIZE];
SSL_CTX *ctx;

#if _WIN32
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")
static HANDLE* mutex_buf = NULL;
#else
static pthread_mutex_t* mutex_buf = NULL;
#endif

int parse_hidns_query_nocopy(const char* inputbuf, const int len, ins_qry_buf** qbuf, struct in_addr** dstIP)
{
	if (len <= INS_QHEADERSIZE) 
		return -2;
	// printf("len = %d, ", len);
	*dstIP = NULL;
	*qbuf = NULL;
	ins_qry_buf* q = (ins_qry_buf*)inputbuf;
	// printf("id = %u, od = %d, qlen = %d, expectlen = %d \n", ntohl(q->header.id), q->header.od, q->header.qnlen, q->header.qnlen + INS_QHEADERSIZE + sizeof(struct in_addr));
	if (q->header.od == 0 || q->header.qnlen + INS_QHEADERSIZE + sizeof(struct in_addr) != len) {
		return -1;
	}
	*qbuf = q;
	*dstIP = (struct in_addr*)(q->buf + q->header.qnlen + INS_QHEADERSIZE);
	return q->header.qnlen + INS_QHEADERSIZE;
}

int parse_hidns_answer_nocopy(const char* inputbuf, const int len, ins_ans_buf** abuf)
{
	if (len < INS_AHEADERSIZE)
		return -2;
	*abuf = NULL;
	ins_ans_buf *a = (ins_ans_buf*)inputbuf;
	// printf("id = %u, od = %d, qlen = %d, expectlen = %d \n", ntohl(a->header.id), a->header.od, a->header.exaplen, a->header.exaplen + INS_AHEADERSIZE);
	if (a->header.od == 0 || a->header.exaplen + INS_AHEADERSIZE > len) {
		return -1;
	}
	*abuf = a;
	return len;
}

static unsigned long id_function(void) {
#ifdef _WIN32
	return (unsigned long)GetCurrentThreadId();
#else
	return (unsigned long) pthread_self();
#endif
}

int THREAD_setup() {
	int i;

#ifdef _WIN32
	mutex_buf = (HANDLE*)malloc(CRYPTO_num_locks() * sizeof(HANDLE));
#else
	mutex_buf = (pthread_mutex_t*) malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
#endif
	if (!mutex_buf)
		return 0;
	for (i = 0; i < CRYPTO_num_locks(); i++)
#ifdef _WIN32
		mutex_buf[i] = CreateMutex(NULL, FALSE, NULL);
#else
		pthread_mutex_init(&mutex_buf[i], NULL);
#endif
	CRYPTO_set_id_callback(id_function);
	CRYPTO_set_locking_callback(locking_function);
	return 1;
}

int THREAD_cleanup() {
	int i;

	if (!mutex_buf)
		return 0;

	CRYPTO_set_id_callback(NULL);
	CRYPTO_set_locking_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks(); i++)
#ifdef _WIN32
		CloseHandle(mutex_buf[i]);
#else
		pthread_mutex_destroy(&mutex_buf[i]);
#endif
	free(mutex_buf);
	mutex_buf = NULL;
	return 1;
}

// FROM CLIENT
int handle_socket_error() {
	printf("[ERROR] ");
	switch (errno) {
	case EINTR:
		/* Interrupted system call.
		* Just ignore.
		*/
		printf("Interrupted system call!\n");
		return 1;
	case EBADF:
		/* Invalid socket.
		* Must close connection.
		*/
		printf("Invalid socket!\n");
		return 0;
		break;
#ifdef EHOSTDOWN
	case EHOSTDOWN:
		/* Host is down.
		* Just ignore, might be an attacker
		* sending fake ICMP messages.
		*/
		printf("Host is down!\n");
		return 1;
#endif
#ifdef ECONNRESET
	case ECONNRESET:
		/* Connection reset by peer.
		* Just ignore, might be an attacker
		* sending fake ICMP messages.
		*/
		printf("Connection reset by peer!\n");
		return 1;
#endif
	case ENOMEM:
		/* Out of memory.
		* Must close connection.
		*/
		printf("Out of memory!\n");
		return 0;
		break;
	case EACCES:
		/* Permission denied.
		* Just ignore, we might be blocked
		* by some firewall policy. Try again
		* and hope for the best.
		*/
		printf("Permission denied!\n");
		return 1;
		break;
	default:
		/* Something unexpected happened */
		printf("Unexpected error! (errno = %d)\n", errno);
		return 0;
		break;
	}
	return 0;
}

int handle_ssl_error(SSL *ssl, int code)
{
	switch (SSL_get_error(ssl, code))
	{
	case SSL_ERROR_NONE:
		break;
	case SSL_ERROR_WANT_WRITE:
		/* Just try again later */
		break;
	case SSL_ERROR_WANT_READ:
		/* continue with reading */
		break;
	case SSL_ERROR_SYSCALL:
		if (!handle_socket_error())
			exit(EXIT_FAILURE);
		break;
	default:
		printf("[ERROR] SSL error!\n");
		exit(EXIT_FAILURE);
		break;
	}
	return 0;
}

void init_hidns_socket()
{
	// int hidns_port = hidns_local_addr.s4.sin_port;

	hidns_fd = socket(hidns_local_addr.ss.ss_family, SOCK_DGRAM, 0);
	if (hidns_fd == -1)
	{
		perror("[ERROR] Failed to open UDP socket for local DNS.\n");
		exit(EXIT_FAILURE);
	}

	if (-1 == bind(hidns_fd, (struct sockaddr*)&hidns_local_addr, sizeof(hidns_local_addr)))
	{
		if (hidns_local_addr.ss.ss_family == AF_INET)
			printf("[ERROR] Failed to bind UDP socket on %s:%d, %s.\n",
			inet_ntop(AF_INET, &hidns_local_addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN),
			ntohs(hidns_local_addr.s4.sin_port), strerror(errno));
		else
			printf("[ERROR] Failed to bind UDP socket on %s:%d, %s.\n",
			inet_ntop(AF_INET, &hidns_local_addr.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN),
			ntohs(hidns_local_addr.s6.sin6_port), strerror(errno));
		exit(EXIT_FAILURE);
	}
}

int init_dtls_socket(struct sockaddr_in *remote_addr)
{
	int dtls_fd = socket(remote_addr->sin_family, SOCK_DGRAM, 0);
	if (dtls_fd < 0)
	{
		perror("[ERROR] Failed to open UDP socket for dtls.\n");
		exit(EXIT_FAILURE);
	}
	connect(dtls_fd, (struct sockaddr *)remote_addr, sizeof(struct sockaddr_in));
	return dtls_fd;
}

int dtls_verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
	// TBD: this should check the cert chain
	// return 1;
	int ret = 0;
	X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
	BIO *certbio = BIO_new(BIO_s_mem());
	if (NULL == certbio) {
		printf("cannot create memory bio\n");
		return 0;
	}
        ret = i2d_X509_bio(certbio, cert);
	if (ret < 0) {
		printf("cannot write cert into memory bio\n");
		BIO_free(certbio);
		return 0;
	}
	int len = BIO_pending(certbio);
	unsigned char* certbuf_der = malloc(len);
        int certbuf_len = BIO_read(certbio, certbuf_der, len);
        if (certbuf_len != len) {
		printf("cannot read cert from memory bio\n");
		BIO_free(certbio);
		free(certbuf_der);
		return 0;
	}
	ret = verify_hidns_x509_cert(certbuf_der, certbuf_len, VERIFY_REQ_ARGTYPE_CERT_DER);
	BIO_free(certbio);
	free(certbuf_der);
	if (ret == 0) return 1;
	else {
		printf("invalid server cert\n");
		return 0;
	}
	// X509* localcert = X509_new();
	// BIO* bio_cert = BIO_new_file("dns.crt", "rb");
	// if (!bio_cert){
	// 	printf("[ERROR] Failed to read local cert.\n");
	// }
	// else {
	// 	PEM_read_bio_X509(bio_cert, &localcert, NULL, NULL);

	// 	X509 *cert = X509_STORE_CTX_get_current_cert(ctx);

	// 	ASN1_BIT_STRING *k1 = X509_get0_pubkey_bitstr(cert);
	// 	ASN1_BIT_STRING *k2 = X509_get0_pubkey_bitstr(localcert);
	// 	if (k1 && k2 && k1->length == k2->length && k1->length > 0 &&
	// 		memcmp(k1->data, k2->data, (size_t)k1->length) == 0)
	// 		ret = 1; /* accept */
	// }
	// BIO_set_close(bio_cert, BIO_CLOSE);
	// BIO_free(bio_cert);
	// X509_free(localcert);
	// return ret;
}

SSL* create_ssl(int fd, struct sockaddr_in *remote_addr)
{
	SSL *ssl = SSL_new(ctx);
	printf("[create ssl] fd = %d, remote port = %d\n", fd, ntohs(remote_addr->sin_port));
	if (ssl == NULL) printf("[ssl error]\n");
	BIO *bio = BIO_new_dgram(fd, BIO_CLOSE);
	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, remote_addr);
	SSL_set_bio(ssl, bio, bio);
	if (ssl == NULL) printf("[ssl error]\n");
	// if (SSL_connect(ssl) < 0) printf("[ssl conn error]\n");
	return ssl;
}

int reconnect(struct session* session)
{

	int retry = 1;
	int connected = -1;
	while (retry < 3)
	{	
		printf("[ERROR] Failed to connect server %s. Reconnect %dth...\n", inet_ntoa(session->server_addr.s4.sin_addr), retry);

		if (SSL_connect(session->ssl) < 0) {	
#ifdef _WIN32
			Sleep(100); //ms
#else
			usleep(100000); //us
#endif
			SSL_free(session->ssl);
			session->ssl = create_ssl(session->dtls_fd, &session->server_addr.s4);
			++retry;
			continue;
		}
		connected = 0;
		break;
	}

	return connected;
}

// END CLIENT

void init_ssl_ctx() {
	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();

	ctx = SSL_CTX_new(DTLS_client_method());
		// SSL_CTX_set_cipher_list(ctx, "AES128-SHA");

	SSL_CTX_set_verify_depth(ctx, 0);
	SSL_CTX_set_read_ahead(ctx, 1);

	// we use validator to verify??
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);
}

#ifdef _WIN32
DWORD WINAPI connection_handle(LPVOID *info) {
#else
void* connection_handle(void *info) {
#endif
	char threadbuf[BUFFER_SIZE];
	char addrbuf[INET6_ADDRSTRLEN];
	struct session *pinfo = (struct session*) info;
	int ret, len;

	pinfo->thread_status = THREAD_STATUS_RUNNING;

#ifndef _WIN32
	pthread_detach(pthread_self());
#endif

	if (SSL_connect(pinfo->ssl) < 0) {
		if (reconnect(pinfo) < 0) {
			goto error_out;
		}
	}

	if (verbose)
	{
		if (pinfo->server_addr.ss.ss_family == AF_INET)
		{
			printf("Connected to %s:%d.\n",
				inet_ntop(AF_INET, &pinfo->server_addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN),
				ntohs(pinfo->server_addr.s4.sin_port));
		}
		else
		{
			printf("Connected to %s:%d.\n",
				inet_ntop(AF_INET6, &pinfo->server_addr.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN),
				ntohs(pinfo->server_addr.s6.sin6_port));
		}

		X509 *cer = SSL_get_peer_certificate(pinfo->ssl);
		if (cer)
		{
			printf("------------------------------------------------------------\n");
#if _WIN32
			printf("%s", X509_NAME_oneline(X509_get_subject_name(SSL_get_peer_certificate(ssl)), buf, 65535));
#else
			X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate(pinfo->ssl)), 1, XN_FLAG_MULTILINE);
#endif

			//EVP_PKEY *pkey = X509_get_pubkey(cer);		

			printf("\n\n Cipher: %s", SSL_CIPHER_get_name(SSL_get_current_cipher(pinfo->ssl)));
			printf("\n------------------------------------------------------------\n\n");
		}
	}
	// finish handshake
	pinfo->handshake_finished = 1;
	if (pinfo->server_addr.ss.ss_family == AF_INET) {
		printf("Thread %lx: connected to %s:%d\n",
			id_function(),
			inet_ntop(AF_INET, &pinfo->server_addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN),
			ntohs(pinfo->server_addr.s4.sin_port));
	}
	else {
		printf("Thread %lx: connected to %s:%d\n",
			id_function(),
			inet_ntop(AF_INET6, &pinfo->server_addr.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN),
			ntohs(pinfo->server_addr.s6.sin6_port));
	}

	fd_set fds;
	struct timeval timewait;
	time_t now;
	ins_ans_buf *abuf;
	int send_count = 0, rcv_count = 0;

	while (pinfo->thread_status == THREAD_STATUS_RUNNING)
	{
		// should write buffer first?
		while (BIO_ctrl_pending(pinfo->for_writing) > 0) {
			len = BIO_read(pinfo->for_writing, threadbuf, sizeof(threadbuf));
			time(&pinfo->active_time);
			ret = SSL_write(pinfo->ssl, threadbuf, len);
			if (ret != -1)
			{
				++send_count;				
				if (verbose)
					printf("Sent %d bytes to DTLS server.\n", (int)len);
			}
			else
			{
				handle_ssl_error(pinfo->ssl, ret);
			}
		}

		timewait.tv_sec = 5;
		timewait.tv_usec = 0;
		FD_ZERO(&fds);
		FD_SET(pinfo->dtls_fd, &fds);
		// printf("thread to %s select dtlsfd = %d\n", inet_ntoa(pinfo->server_addr.s4.sin_addr), pinfo->dtls_fd);
		ret = select(pinfo->dtls_fd + 1, &fds, NULL, NULL, &timewait);
		if (ret > 0 && FD_ISSET(pinfo->dtls_fd, &fds))
		{
			if (SSL_get_shutdown(pinfo->ssl) & SSL_RECEIVED_SHUTDOWN)
			{
				pinfo->handshake_finished = 0;
				goto error_out;
				// printf("[ERROR] SSL has shutdown.\n");
				// if (reconnect(pinfo) < 0) goto error_out;
				// else pinfo->handshake_finished = 1;
			} 
			else {
				len = SSL_read(pinfo->ssl, threadbuf, sizeof(threadbuf));
				if (len > 0) {
					++rcv_count;
					if (verbose)
						printf("Received %d bytes from DTLS server.\n", len);
					if (parse_hidns_answer_nocopy(threadbuf, len, &abuf) > 0) {
						transrecord *record = hashmap_delete(pinfo->transmap, &(transrecord){ .transaction_id=abuf->header.id });
						if (record != NULL) {	
							len = sendto(hidns_fd, threadbuf, len, 0, (struct sockaddr *)&record->client_addr, sizeof(record->client_addr));
							if (len == -1)
							{
								perror("[ERROR] Failed to send hiDNS response.\n");
							}
							// free(record);
						}
					}
				}
				else if (len == 0) {
					if (SSL_get_shutdown(pinfo->ssl) & SSL_RECEIVED_SHUTDOWN)
					{
						pinfo->handshake_finished = 0;
						goto error_out;
						// printf("[ERROR] SSL has shutdown.\n");
						// if (reconnect(pinfo) < 0) goto error_out;
						// else pinfo->handshake_finished = 1;
					}
				} 
				else {
					handle_ssl_error(pinfo->ssl, len);
				}
			}
		}
		else {
			if (pinfo->send_count + send_count != rcv_count) {
				time(&now);
				if (now - pinfo->active_time > HIDNS_TIMEOUT) {
					printf("[ERROR] server %s respond timeout!\n", inet_ntoa(pinfo->server_addr.s4.sin_addr));
					SSL_shutdown(pinfo->ssl);
					goto error_out;
				}
			}
		}
	}

error_out:
	pinfo->thread_status = THREAD_STATUS_STOPPING;
	printf("[INFO] Terminate session with %s.\n", inet_ntoa(pinfo->server_addr.s4.sin_addr));
#if _WIN32
	closesocket(pinfo->dtls_fd);
#else
	close(pinfo->dtls_fd);
#endif
	SSL_free(pinfo->ssl);
	pinfo->thread_status = THREAD_STATUS_DEAD;
#if _WIN32
	ExitThread(0);
#else
	pthread_exit((void *)NULL);
#endif
}

void start() {

#if _WIN32
	DWORD tid;
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
#else
	pthread_t tid;
#endif
	union mysockaddr hidns_from_addr;
	socklen_t from_len = sizeof(hidns_from_addr);
	int ret, len, qlen, cursessioncount;
	struct timeval timeout;
	time_t now, lastcheck;
	fd_set fds;
	session* current_session = NULL;
	ins_qry_buf *qbuf;
	struct sockaddr_in dst;
	dst.sin_family = AF_INET;
	dst.sin_port = htons(DTLS_SERVER_LPORT);
	struct in_addr *dstIP;
	BIO *for_reading;
	BIO *for_writing;
	
	memset((void *)&hidns_from_addr, 0, sizeof(struct sockaddr_storage));

	init_hidns_socket();
	init_ssl_ctx();
	THREAD_setup();
	
	time(&lastcheck);
	while (1) {
		cursessioncount = get_session_count(session_list);
		if (sessioncount != cursessioncount) {
			sessioncount = cursessioncount;
			printf("The number of clients becomes %d\n", cursessioncount);
		}

		timeout.tv_sec = 5;
		timeout.tv_usec = 0;
		FD_ZERO(&fds);
		FD_SET(hidns_fd, &fds);

		ret = select(hidns_fd + 1, &fds, NULL, NULL, &timeout);
		if (ret > 0)
		{
			if (FD_ISSET(hidns_fd, &fds))
			{
				len = recvfrom(hidns_fd, buf, BUFFER_SIZE, 0, (struct sockaddr*)&hidns_from_addr, &from_len);
				if ((qlen = parse_hidns_query_nocopy(buf, len, &qbuf, &dstIP)) < 0)
				{
					if (hidns_from_addr.ss.ss_family == AF_INET)
					{
						printf("[ERROR] Failed to receive hiDNS data from %s:%d.\n",
							inet_ntop(AF_INET, &hidns_from_addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN),
							ntohs(hidns_from_addr.s4.sin_port));
					}
					else
					{
						printf("[ERROR] Failed to receive hiDNS data from %s:%d.\n",
							inet_ntop(AF_INET6, &hidns_from_addr.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN),
							ntohs(hidns_from_addr.s4.sin_port));
					}					
				}
				else
				{
					if (verbose)
					{
						if (hidns_from_addr.ss.ss_family == AF_INET)
						{
							printf("Received hiDNS request from %s:%d, length:%d.\n",
								inet_ntop(AF_INET, &hidns_from_addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN),
								ntohs(hidns_from_addr.s4.sin_port), len);
						}
						else
						{
							printf("Received hiDNS request from %s:%d, length:%d.\n",
								inet_ntop(AF_INET6, &hidns_from_addr.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN),
								ntohs(hidns_from_addr.s6.sin6_port), len);
						}
					}

					dst.sin_addr = *dstIP;
					transrecord record = {qbuf->header.id, hidns_from_addr.s4};
					current_session = get_session(session_list, *(union mysockaddr*)&dst);
					if (current_session == NULL) printf("session not found\n");
					if (current_session == NULL || current_session->thread_status != THREAD_STATUS_RUNNING) {
						// need to add a new session
						printf("new session!\n");
						int dtls_fd = init_dtls_socket(&dst);

						SSL *ssl = create_ssl(dtls_fd, &dst);
						// BIO *bio = BIO_new_dgram(dtls_fd, BIO_CLOSE);
						// BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, dst);
						// SSL_set_bio(ssl, bio, bio);		

						// set up the memory-buffer BIOs. TBD
						if (current_session == NULL) {
							for_reading = BIO_new(BIO_s_mem());
							for_writing = BIO_new(BIO_s_mem());
							BIO_set_mem_eof_return(for_reading, -1);
							BIO_set_mem_eof_return(for_writing, -1);
						} else {
							for_reading = current_session->for_reading;
							for_writing = current_session->for_writing;
						}
						current_session = add_session(&session_list, *(union mysockaddr*)&dst, hidns_from_addr, ssl, for_reading, for_writing, dtls_fd);
						// SSL_set_bio(current_session->ssl, current_session->for_reading, current_session->for_writing);

						// meaning is not known. TBD
						// BIO_dgram_set_peer(current_session->for_writing, &current_session->server_addr);
						hashmap_set(current_session->transmap, &record);
						BIO_write(current_session->for_writing, buf, qlen);

#ifdef _WIN32
						if (CreateThread(NULL, 0, connection_handle, current_session, 0, &tid) == NULL) {
							exit(EXIT_FAILURE);
						}
#else
						if (pthread_create(&tid, NULL, connection_handle, current_session) != 0) {
							//  perror("pthread_create");
							exit(EXIT_FAILURE);
						}
#endif
					}
					else
					{	// an active session found
						// printf("find session!\n");
						hashmap_set(current_session->transmap, &record);
						if (current_session->handshake_finished != 1)
							BIO_write(current_session->for_reading, buf, qlen);
						else {
							// send this buf
							time(&current_session->active_time);
							ret = SSL_write(current_session->ssl, buf, qlen);
							if (ret != -1)
							{
								++current_session->send_count;
								if (verbose)
									printf("Sent %d bytes to DTLS server.\n", (int)len);
							}
							else
							{
								handle_ssl_error(current_session->ssl, ret);
							}
						}
						// time(&current_session->active_time);
					}
				}
			} else {
				printf("something wrong in main thread!\n");
			}
		}
		
		// session check
		time(&now);
		if (now - lastcheck < 2) {
			continue;
		} else {
			lastcheck = now;
		}
		current_session = session_list;
		struct session *removenode = NULL;
		while (current_session != NULL) {
			if (current_session->thread_status == THREAD_STATUS_DEAD) {
				removenode = current_session;
				current_session = current_session->next;
				remove_session(&session_list, &removenode);
				printf("A session removed.\n");
				continue;
			}
			else {
				current_session = current_session->next;
			}
		}
	}
	THREAD_cleanup();
#ifdef _WIN32
	WSACleanup();
#endif
}

int main(int argc, char **argv) 
{
	char *hidns_address = "127.0.0.1";
	int hidns_port = DTLS_CLIENT_LPORT;

#if _WIN32
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

	memset((void *)&hidns_local_addr, 0, sizeof(struct sockaddr_storage));
	if (inet_pton(AF_INET, hidns_address, &hidns_local_addr.s4.sin_addr) == 1)
	{
		hidns_local_addr.s4.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
		hidns_local_addr.s4.sin_len = sizeof(struct sockaddr_in);
#endif
		hidns_local_addr.s4.sin_port = htons(hidns_port);
	}
	else if (inet_pton(AF_INET6, hidns_address, &hidns_local_addr.s6.sin6_addr) == 1)
	{
		hidns_local_addr.s6.sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
		hidns_local_addr.s6.sin6_len = sizeof(struct sockaddr_in6);
#endif
		hidns_local_addr.s6.sin6_port = htons(hidns_port);
	}
	else
	{
		printf("[ERROR] Local hidns address: %s.\n", hidns_address);
		exit(EXIT_FAILURE);
	}

	start();
	return 0;
}
