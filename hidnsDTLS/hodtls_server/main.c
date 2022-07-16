#include "session.h"

#define BUFFER_SIZE          	65536
#define COOKIE_SECRET_LENGTH 	16
#define SESSION_TIMEOUT 	10	//second
#define HANDSHAKE_TIMEOUT	10

#define DTLS_SERVER_LPORT	5554
#define HIDNS_LISTEN_PORT	5553

int verbose = 1;
unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
int cookie_initialized = 0;
int openssl_addr_index = 0;
session *session_list = NULL;
int client_count = 0;
int sessioncount = 0;

char buf[BUFFER_SIZE];

union mysockaddr server_addr, hidns_addr;
SSL_CTX *ctx;

#if _WIN32
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")
static HANDLE* mutex_buf = NULL;
#else
static pthread_mutex_t* mutex_buf = NULL;
#endif

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

int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
	unsigned char *buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength;
	union mysockaddr peer;

	// Initialize a random secret
	if (!cookie_initialized) {
		if (!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH)) {
			printf("[ERROR] Failed to setting random cookie secret.\n");
			return 0;
		}
		cookie_initialized = 1;
	}

	// Read peer information
	// (void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);
	void *data = SSL_get_ex_data(ssl, openssl_addr_index);
	memcpy(&peer, data, sizeof(peer));

	// Create buffer with peer's address and port
	length = 0;
	switch (peer.ss.ss_family) {
	case AF_INET:
		length += sizeof(struct in_addr);
		break;
	case AF_INET6:
		length += sizeof(struct in6_addr);
		break;
	default:
		OPENSSL_assert(0);
		break;
	}
	length += sizeof(in_port_t);
	buffer = (unsigned char*)OPENSSL_malloc(length);

	if (buffer == NULL) {
		printf("[ERROR] Out of memory.\n");
		return 0;
	}

	switch (peer.ss.ss_family) {
	case AF_INET:
		memcpy(buffer,
			&peer.s4.sin_port,
			sizeof(in_port_t));
		memcpy(buffer + sizeof(peer.s4.sin_port),
			&peer.s4.sin_addr,
			sizeof(struct in_addr));
		break;
	case AF_INET6:
		memcpy(buffer,
			&peer.s6.sin6_port,
			sizeof(in_port_t));
		memcpy(buffer + sizeof(in_port_t),
			&peer.s6.sin6_addr,
			sizeof(struct in6_addr));
		break;
	default:
		OPENSSL_assert(0);
		break;
	}

	// Calculate HMAC of buffer using the secret
	HMAC(EVP_sha1(), (const void*)cookie_secret, COOKIE_SECRET_LENGTH,
		(const unsigned char*)buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	memcpy(cookie, result, resultlength);
	*cookie_len = resultlength;

	return 1;
}

int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len) {
	unsigned char *buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength;
	union mysockaddr peer;

	// If secret isn't initialized yet, the cookie can't be valid
	if (!cookie_initialized)
		return 0;

	// Read peer information
	// (void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);
	void *data = SSL_get_ex_data(ssl, openssl_addr_index);
	memcpy(&peer, data, sizeof(peer));

	// Create buffer with peer's address and port
	length = 0;
	switch (peer.ss.ss_family) {
	case AF_INET:
		length += sizeof(struct in_addr);
		break;
	case AF_INET6:
		length += sizeof(struct in6_addr);
		break;
	default:
		OPENSSL_assert(0);
		break;
	}
	length += sizeof(in_port_t);
	buffer = (unsigned char*)OPENSSL_malloc(length);

	if (buffer == NULL){
		printf("[ERROR] Out of memory.\n");
		return 0;
	}

	switch (peer.ss.ss_family) {
	case AF_INET:
		memcpy(buffer, &peer.s4.sin_port, sizeof(in_port_t));
		memcpy(buffer + sizeof(in_port_t), &peer.s4.sin_addr, sizeof(struct in_addr));
		break;
	case AF_INET6:
		memcpy(buffer, &peer.s6.sin6_port, sizeof(in_port_t));
		memcpy(buffer + sizeof(in_port_t), &peer.s6.sin6_addr, sizeof(struct in6_addr));
		break;
	default:
		OPENSSL_assert(0);
		break;
	}

	// Calculate HMAC of buffer using the secret
	HMAC(EVP_sha1(), (const void*)cookie_secret, COOKIE_SECRET_LENGTH,
		(const unsigned char*)buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0)
		return 1;

	return 0;
}

void init_ssl_ctx() {
	OpenSSL_add_ssl_algorithms();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(DTLS_server_method());
	// We accept AES128-SHA for test
// 	SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-"
//       "SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256");//ALL:NULL:eNULL:aNULL
	SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
	SSL_CTX_set_ecdh_auto(ctx, 1);
	if (!SSL_CTX_use_certificate_file(ctx, "dns.crt", SSL_FILETYPE_PEM)) {
		printf("[ERROR] No certificate found!\n");
		exit(EXIT_FAILURE);
	}

	if (!SSL_CTX_use_PrivateKey_file(ctx, "dns.key", SSL_FILETYPE_PEM)) {
		printf("[ERROR] No private key found!\n"); 
		exit(EXIT_FAILURE);
	}

	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	if (!SSL_CTX_check_private_key(ctx)) {
		printf("[ERROR] Invalid private key!\n");
		exit(EXIT_FAILURE);
	}
	
	SSL_CTX_set_read_ahead(ctx, 1);
	SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
	SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);
}

#ifdef _WIN32
DWORD WINAPI connection_handle(LPVOID *info) {
#else
void* connection_handle(void *info) {
#endif
	char threadbuf[BUFFER_SIZE];
	char addrbuf[INET6_ADDRSTRLEN];
	struct session *pinfo = (struct session*) info;
	int ret, err_code, len;

	pinfo->thread_status = THREAD_STATUS_RUNNING;

#ifndef _WIN32
	pthread_detach(pthread_self());
#endif

	// start handshake
	do{
		ret = SSL_accept(pinfo->ssl);
	} while (ret == 0);

	if (ret < 0) {
		err_code = ERR_get_error();
		if (err_code != SSL_ERROR_NONE)
		{
			pinfo->thread_status = THREAD_STATUS_DEAD;
			printf("[ERROR] SSL handshake error: %s\n", ERR_error_string(err_code, threadbuf));
#if _WIN32
			ExitThread(0);
#else
			pthread_exit((void *)NULL);
#endif
		}
	}
	OSSL_HANDSHAKE_STATE state = SSL_get_state(pinfo->ssl);
	if (state == DTLS_ST_SW_HELLO_VERIFY_REQUEST) {
		pinfo->ssl_status = SSL_STATUS_OK;
	}
	else {
		pinfo->ssl_status = SSL_STATUS_ERR;
		if (state == TLS_ST_BEFORE) {
			printf("[ERROR] Bad data, failed to handshake.\n");
		}
		pinfo->thread_status = THREAD_STATUS_DEAD;
		return 0;
	}
	//finish handshake
	time_t begin;
	time_t now;
	time(&begin);
	while (1) {
#ifdef _WIN32
		Sleep(100); //ms
#else
		usleep(100000); //us
#endif
		time(&now);
		state = SSL_get_state(pinfo->ssl);
		if (state == TLS_ST_OK) {
			break;
		}
		else if (now - begin > HANDSHAKE_TIMEOUT) {
			printf("[ERROR] SSL handshake timed out.\n");
			pinfo->ssl_status = SSL_STATUS_ERR;
			pinfo->thread_status = THREAD_STATUS_DEAD;
			break;
		}
	}


	if (pinfo->client_addr.ss.ss_family == AF_INET) {
		printf("Thread %lx: accepted connection from %s:%d\n",
			id_function(),
			inet_ntop(AF_INET, &pinfo->client_addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN),
			ntohs(pinfo->client_addr.s4.sin_port));
	}
	else {
		printf("Thread %lx: accepted connection from %s:%d\n",
			id_function(),
			inet_ntop(AF_INET6, &pinfo->client_addr.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN),
			ntohs(pinfo->client_addr.s6.sin6_port));
	}

	union mysockaddr from_addr;
	socklen_t from_len = sizeof(from_addr);
	fd_set hidns_fds;
	struct timeval hidns_timeout;
	while (pinfo->thread_status == THREAD_STATUS_RUNNING)
	{
		hidns_timeout.tv_sec = 0;
		hidns_timeout.tv_usec = 100;
		FD_ZERO(&hidns_fds);
		FD_SET(pinfo->hidns_fd, &hidns_fds);
		ret = select(pinfo->hidns_fd + 1, &hidns_fds, NULL, NULL, &hidns_timeout);
		if (ret > 0 && FD_ISSET(pinfo->hidns_fd, &hidns_fds))
		{
			len = recvfrom(pinfo->hidns_fd, threadbuf, BUFFER_SIZE, 0, (struct sockaddr*)&from_addr, &from_len);
			if (len == -1) {
				printf("[Error] Failed to receive data from hidns server.\n");
			}
			else {
				if (verbose)
					printf("Received %d bytes from hidns server.\n", len);

				if (pinfo->ssl_status == SSL_STATUS_OK && !(SSL_get_shutdown(pinfo->ssl) & SSL_RECEIVED_SHUTDOWN)) {
					if (SSL_write(pinfo->ssl, threadbuf, len) > 0) {
						if (verbose)
							printf("Sent %d bytes to dtls client.\n", len);
					}
					else {
						printf("[Error] Failed to send data to dtls client.\n");
					}
				}
				else {
					printf("[Error] Failed to send data to dtls client: SSL has shutdown.\n");
					pinfo->thread_status = THREAD_STATUS_DEAD;
#if _WIN32
					ExitThread(0);
#else
					pthread_exit((void *)NULL);
#endif
				}
			}
		}

#ifdef _WIN32
		Sleep(10); //ms
#else
		usleep(10000); //us
#endif
	}
	pinfo->thread_status = THREAD_STATUS_DEAD;
	return 0;
}

void start() {
	int dtls_fd;
	const int on = 1, off = 0;
	union mysockaddr client_addr;
	time_t now;

#if _WIN32
	DWORD tid;
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
#else
	pthread_t tid;
#endif

	THREAD_setup();
	init_ssl_ctx();

	dtls_fd = socket(server_addr.ss.ss_family, SOCK_DGRAM, 0);
	if (dtls_fd < 0) {
		exit(EXIT_FAILURE);
	}

	setsockopt(dtls_fd, SOL_SOCKET, SO_REUSEADDR, (const void*)&on, (socklen_t) sizeof(on));
#ifdef SO_REUSEPORT
	setsockopt(dtls_fd, SOL_SOCKET, SO_REUSEPORT, (const void*)&on, (socklen_t) sizeof(on));
#endif

	if (server_addr.ss.ss_family == AF_INET) {
		if (-1 == bind(dtls_fd, (const struct sockaddr *) &server_addr, sizeof(struct sockaddr_in))) {
			perror("[Error] Failed to open UDP socket for DTLS\n");
			exit(EXIT_FAILURE);
		}
	}
	else {
		setsockopt(dtls_fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&off, sizeof(off));
		if (-1 == bind(dtls_fd, (const struct sockaddr *) &server_addr, sizeof(struct sockaddr_in6))) {
			perror("[Error] Failed to open UDP socket for DTLS\n");
			exit(EXIT_FAILURE);
		}
	}

	int ret;
	int len = 0;

	socklen_t from_len = sizeof(client_addr);

	struct timeval dtls_timeout;
	fd_set fds;
	memset(&client_addr, 0, sizeof(struct sockaddr_storage));

	session* current_session = NULL;
	while (1) {
		sessioncount = get_session_count(session_list);
		if (sessioncount != client_count) {
			client_count = sessioncount;
			printf("The number of clients becomes %d\n", client_count);
		}

		dtls_timeout.tv_sec = 0;
		dtls_timeout.tv_usec = 100;
		FD_ZERO(&fds);
		FD_SET(dtls_fd, &fds);		
		ret = select(dtls_fd + 1, &fds, NULL, NULL, &dtls_timeout);
		if (ret > 0 && FD_ISSET(dtls_fd, &fds)) {
			if (server_addr.ss.ss_family == AF_INET) {
				len = recvfrom(dtls_fd, buf, BUFFER_SIZE, 0, (struct sockaddr *) &client_addr, &from_len);
			}
			else {
				len = recvfrom(dtls_fd, buf, BUFFER_SIZE, 0, (struct sockaddr *) &client_addr, &from_len);
			}
			if (len > 0) {
				current_session = get_session(session_list, client_addr);
				if (current_session == NULL) {
					printf("new session!\n");
					SSL *ssl = SSL_new(ctx);
					// set up the memory-buffer BIOs
					BIO *for_reading = BIO_new(BIO_s_mem());
					BIO *for_writing = BIO_new(BIO_s_mem());
					BIO_set_mem_eof_return(for_reading, -1);
					BIO_set_mem_eof_return(for_writing, -1);

					int hidns_fd = socket(hidns_addr.ss.ss_family, SOCK_DGRAM, 0);
					if (hidns_fd < 0)
					{
						exit(EXIT_FAILURE);
					}

					current_session = add_session(&session_list, server_addr, client_addr, ssl, for_reading, for_writing, hidns_fd);
					//set peer
					BIO_dgram_set_peer(current_session->for_reading, &current_session->client_addr);
					//bind them together
					SSL_set_bio(current_session->ssl, current_session->for_reading, current_session->for_writing);

					SSL_set_accept_state(current_session->ssl);
					//add ex data
					char indexname[] = "hiDnsOverDtls";
					if (!openssl_addr_index)
						openssl_addr_index = SSL_get_ex_new_index(0, indexname, NULL, NULL, NULL);
					SSL_set_ex_data(current_session->ssl, openssl_addr_index, &current_session->client_addr);
					SSL_set_options(current_session->ssl, SSL_OP_COOKIE_EXCHANGE);

					BIO_write(current_session->for_reading, buf, len);

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
				else {
					printf("find session!\n");
					// write the received buffer from the UDP socket to the memory-based input bio
					BIO_write(current_session->for_reading, buf, len);

					// Tell openssl to process the packet now stored in the memory bio
					// if (SSL_get_state(current_session->ssl) == TLS_ST_OK) {
					if (current_session->ssl_status == SSL_STATUS_OK) {
						// printf("buflen=%d\n", len);
						len = SSL_read(current_session->ssl, buf, BUFFER_SIZE);
						// printf("readlen=%d\n", len);
						if (len < 0 && SSL_get_state(current_session->ssl) == TLS_ST_OK) {
							if (current_session->handshake_finished) {
								current_session->thread_status = THREAD_STATUS_DEAD;
								printf("bad session resuse\n");	
							}
							else {
								current_session->handshake_finished = 1;
								printf("handshake confirmed\n");	
							}
							// printf("TLS is reset\n");
						}
						time(&current_session->active_time);
						if (len > 0) {
							if (verbose) {
								if (current_session->client_addr.ss.ss_family == AF_INET) {
									printf("Received %d bytes from %s:%d\n", len,
										inet_ntop(AF_INET, &current_session->client_addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN),
										ntohs(current_session->client_addr.s4.sin_port));
								}
								else {
									printf("Received %d bytes from %s:%d\n", len,
										inet_ntop(AF_INET6, &current_session->client_addr.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN),
										ntohs(current_session->client_addr.s6.sin6_port));
								}

							}

							len = sendto(current_session->hidns_fd, buf, len, 0, (struct sockaddr *)&hidns_addr, sizeof(hidns_addr));
							if (len == -1) {
								printf("[Error] Failed to send data to hidns server.\n");
							}
							else {
								if (verbose)
									printf("Sent %d bytes to hidns server.\n", len);
							}
						}
					}
				}
			}
		}

#ifdef _WIN32
		Sleep(10); //ms
#else
		usleep(10000); //us
#endif
		
		//session
		time(&now);
		current_session = session_list;
		struct session *removenode = NULL;
		while (current_session != NULL) {
			if (current_session->thread_status == THREAD_STATUS_RUNNING){
				if (current_session->ssl_status == SSL_STATUS_ERR) {
					current_session->thread_status = THREAD_STATUS_STOPPING;
				}
				else if (SSL_get_shutdown(current_session->ssl) & SSL_RECEIVED_SHUTDOWN) {
					current_session->thread_status = THREAD_STATUS_STOPPING;
					if (verbose)
						printf("A session was shutdown.\n");
				}
				else if (now - current_session->active_time > SESSION_TIMEOUT) {
					SSL_shutdown(current_session->ssl);
					current_session->thread_status = THREAD_STATUS_STOPPING;
					if (verbose) {
						printf("A session timed out.\n");						
					}
				}
			}
			if (current_session->thread_status == THREAD_STATUS_DEAD) {
				removenode = current_session;
				current_session = current_session->next;
				remove_session(&session_list, &removenode);
				printf("A session removed.\n");
				continue;
			}
			else {
				if (BIO_ctrl_pending(current_session->for_writing) > 0) {
					// Read the data out of the for_writing bio
					int outsize = BIO_read(current_session->for_writing, buf, sizeof(buf));

					// send it out the udp port
					if (current_session->client_addr.ss.ss_family == AF_INET) {
						len = sendto(dtls_fd, buf, outsize, 0, (const struct sockaddr *)&current_session->client_addr.s4, sizeof(struct sockaddr_in));
					}
					else {
						len = sendto(dtls_fd, buf, outsize, 0, (const struct sockaddr *) &current_session->client_addr.s6, sizeof(struct sockaddr_in6));
					}
				}
				current_session = current_session->next;
			}
		}
	}
	THREAD_cleanup();
#ifdef _WIN32
	WSACleanup();
#endif
}

int main(int argc, char **argv) {
	char *server_address = "0.0.0.0";
	unsigned short server_port = DTLS_SERVER_LPORT;

	char *hidns_address = "127.0.0.1";
	unsigned short hidns_port = HIDNS_LISTEN_PORT;

	memset(&server_addr, 0, sizeof(struct sockaddr_storage));
	if (strlen(server_address) == 0) {
		server_addr.s6.sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
		server_addr.s6.sin6_len = sizeof(struct sockaddr_in6);
#endif
		server_addr.s6.sin6_addr = in6addr_any;
		server_addr.s6.sin6_port = htons(server_port);
	}
	else {
		if (inet_pton(AF_INET, server_address, &server_addr.s4.sin_addr) == 1) {
			server_addr.s4.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
			server_addr.s4.sin_len = sizeof(struct sockaddr_in);
#endif
			server_addr.s4.sin_port = htons(server_port);
		}
		else if (inet_pton(AF_INET6, server_address, &server_addr.s6.sin6_addr) == 1) {
			server_addr.s6.sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
			server_addr.s6.sin6_len = sizeof(struct sockaddr_in6);
#endif
			server_addr.s6.sin6_port = htons(server_port);
		}
		else {
			printf("[Error] DTLS server address %s\n", server_address);
			exit(EXIT_FAILURE);
		}
	}

	memset(&hidns_addr, 0, sizeof(struct sockaddr_storage));
	if (inet_pton(AF_INET, hidns_address, &hidns_addr.s4.sin_addr) == 1) {
		hidns_addr.s4.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
		hidns_addr.s4.sin_len = sizeof(struct sockaddr_in);
#endif
		hidns_addr.s4.sin_port = htons(hidns_port);
	}
	else if (inet_pton(AF_INET6, hidns_address, &hidns_addr.s6.sin6_addr) == 1) {
		hidns_addr.s6.sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
		hidns_addr.s6.sin6_len = sizeof(struct sockaddr_in6);
#endif
		hidns_addr.s6.sin6_port = htons(hidns_port);
	}
	else {
		printf("[Error] hidns server address %s\n", hidns_address);
		exit(EXIT_FAILURE);
	}

	start();
	return 0;
}
