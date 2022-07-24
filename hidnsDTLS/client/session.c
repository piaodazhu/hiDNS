#include "session.h"

int user_compare(const void *a, const void *b, void *udata) {
    if (a == NULL || b == NULL) return -1;
	const transrecord *ta = a;
    const transrecord *tb = b;
    return ta->transaction_id != tb->transaction_id;
}

bool user_iter(const void *item, void *udata) {
    const transrecord *transaction = item;
    printf("transaction id = %d, from port %u\n", transaction->transaction_id, ntohs(transaction->client_addr.sin_port));
    return true;
}

uint64_t user_hash(const void *item, uint64_t seed0, uint64_t seed1) {
    const transrecord *transaction = item;
	return hashmap_murmur(&transaction->transaction_id, sizeof(transaction->transaction_id), seed0, seed1);
}

void printList(session *session_list)
{
	session* current = session_list;
	if (NULL == current)
	{
		printf("session count = 0\n");
	}
	else
	{
		while (NULL != current)
		{
			if (current->server_addr.ss.ss_family == 2)
			{
				printf("ip:%s ,port:%d,ssl_status:%d, dtls_active_time:%ld\n",
					inet_ntop(AF_INET, &current->server_addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN),
					ntohs(current->server_addr.s4.sin_port),
					current->ssl_status,
					current->active_time);
			}
			else
			{
				printf("ip:%s ,port:%d,ssl_status:%d, start_time:%ld\n",
					inet_ntop(AF_INET6, &current->server_addr.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN),
					ntohs(current->server_addr.s6.sin6_port),
					current->ssl_status,
					current->active_time);
			}
			current = current->next;
		}
		printf("\n");
	}
}

int get_session_count(session *session_list)
{
	int count = 0;
	session* pNode = session_list;
	while (NULL != pNode)
	{
		count++;
		pNode = pNode->next;
	}
	return count;
}

session *get_session(session *session_list, union mysockaddr addr)
{
	session *current = session_list;

	if (NULL == session_list)
	{
		return NULL;
	}

	while ((NULL != current) && (memcmp(&(current->server_addr.s4), &addr, sizeof(current->server_addr.s4)) != 0))
	{
		current = current->next;
	}

	return current;
}

session *add_session(session **psession_list, union mysockaddr server_addr,
union mysockaddr client_addr, SSL *ssl, BIO *for_reading,
	BIO *for_writing, int dtls_fd)
{
	session *insert = get_session(*psession_list, server_addr);
	if (insert == NULL) {
		insert = (session *)malloc(sizeof(session));
		memset(insert, 0, sizeof(session));
		memcpy(&insert->server_addr.s4, &server_addr.s4, sizeof(server_addr.s4));
		memcpy(&insert->client_addr.s4, &client_addr.s4, sizeof(client_addr.s4));
		insert->ssl = ssl;
		insert->ssl_status = SSL_STATUS_HANDSHAKE;
		insert->thread_status = THREAD_STATUS_NEW;
		insert->handshake_finished = 0;
		insert->for_reading = for_reading;
		insert->for_writing = for_writing;
		insert->dtls_fd = dtls_fd;
		insert->send_count = 0;
		insert->transmap = hashmap_new(sizeof(transrecord), 0, 0, 0, user_hash, user_compare, NULL, NULL);
		time(&insert->active_time);

		if (*psession_list != NULL)
			(*psession_list)->prev = insert;
		insert->next = *psession_list;
		*psession_list = insert;
	}
	else {
		memcpy(&insert->client_addr.s4, &client_addr.s4, sizeof(client_addr.s4));
		insert->ssl = ssl;
		insert->ssl_status = SSL_STATUS_HANDSHAKE;
		insert->thread_status = THREAD_STATUS_NEW;
		insert->handshake_finished = 0;
		insert->for_reading = for_reading;
		insert->for_writing = for_writing;
		insert->dtls_fd = dtls_fd;
		insert->send_count = 0;
		hashmap_clear(insert->transmap, true);
		time(&insert->active_time);
	}
	return insert;
}


int remove_session(session **psession_list, session **psession)
{
	if ((*psession)->next != NULL)
		(*psession)->next->prev = (*psession)->prev;
	if ((*psession)->prev != NULL)
		(*psession)->prev->next = (*psession)->next;
	else
		*psession_list = (*psession)->next;
	hashmap_free((*psession)->transmap);
	free(*psession);
	return 1;
}
