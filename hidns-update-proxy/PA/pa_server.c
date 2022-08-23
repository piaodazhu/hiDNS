#include "pa_server.h"

prefix_trie_t *PrefixTrie;
workqueue_t JobQueue;
int DebugType;

void debugInfo(const char *format, ...)
{
	if (DebugType != DEBUG_NONE) {
		char buf[256];
		va_list args;
		va_start(args, format);
		vsnprintf(buf, 256, format, args);
		va_end(args);
		if (DebugType == DEBUG_PRINT) {
			printf("%s", buf);
		} 
		else if (DebugType == DEBUG_LOG) {
			// TBD: write to log.
		}
	}
}

session_ctx_t* session_accept(int __listenfd, SSL_CTX* sslctx)
{
	struct sockaddr_in addr;
        unsigned int len = sizeof(addr);
	int clientfd;
	session_ctx_t* ctx = (session_ctx_t *)malloc(sizeof(session_ctx_t));
	ctx->cmdbuf = NULL;
	ctx->ssl = NULL;
	ctx->clientfd = accept(__listenfd, (struct sockaddr*)&addr, &len);
	ntySetNonblock(ctx->clientfd);
	if (sslctx == NULL) {
		debugInfo("accept new client [%s:%d].\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
		return ctx;
	}
	ctx->ssl = SSL_new(sslctx);
	SSL_set_fd(ctx->ssl, ctx->clientfd);

        if (SSL_accept(ctx->ssl) <= 0) {
		ERR_print_errors_fp(stderr);
		SSL_shutdown(ctx->ssl);
		SSL_free(ctx->ssl);
		close(ctx->clientfd);
		free(ctx);
		return NULL;
        }
	return ctx;
}

void session_close(session_ctx_t *__sctx)
{
	session_cmdlist_free(__sctx);
	if (__sctx->ssl != NULL) {
		SSL_shutdown(__sctx->ssl);
        	SSL_free(__sctx->ssl);
	}
	close(__sctx->clientfd);
	free(__sctx);
}

int session_readn(session_ctx_t *__sctx, void *__buf, size_t __nbytes)
{
	int ret;
	if (__sctx->ssl == NULL) {
		ret = recv(__sctx->clientfd, __buf, __nbytes, 0);
		if (ret < 0) {	// retry once
			ret = recv(__sctx->clientfd, __buf, __nbytes, 0);
		}
		if (ret != __nbytes) {
			debugInfo("Failed to read from clientfd.\n");
			ret = 0;
		}
	} else {
		ret = SSL_read(__sctx->ssl, __buf, __nbytes);
		if (ret < 0) {	// retry once
			ret = SSL_read(__sctx->ssl, __buf, __nbytes);
		}
		if (ret != __nbytes) {
			debugInfo("Failed to read from clientssl.\n");
			ret = 0;
		}
	}
	return ret;
}

int session_writen(session_ctx_t *__sctx, const void *__buf, size_t __nbytes)
{
	int ret;
	if (__sctx->ssl == NULL) {
		ret = send(__sctx->clientfd, __buf, __nbytes, 0);
		if (ret < 0) {	// retry once
			ret = send(__sctx->clientfd, __buf, __nbytes, 0);
		}
		if (ret != __nbytes) {
			debugInfo("Failed to write to clientfd.\n");
			ret = 0;
		}
	} else {
		ret = SSL_write(__sctx->ssl, __buf, __nbytes);
		if (ret < 0) {	// retry once
			ret = SSL_write(__sctx->ssl, __buf, __nbytes);
		}
		if (ret != __nbytes) {
			debugInfo("Failed to write to clientssl.\n");
			ret = 0;
		}
	}
	return ret;
}

int server_prefixtrie_init()
{
	PrefixTrie = prefix_trie_load(PREFIX_DUMPFNAME);
	if (PrefixTrie == NULL)
	{
		PrefixTrie = prefix_trie_init(SERVER_PREFIX, strlen(SERVER_PREFIX));
		prefix_trie_dump(PrefixTrie, PREFIX_DUMPFNAME);
		debugInfo("Initialize a new prefix trie.\n");
		return 1;
	}
	debugInfo("Load prefix trie from %s.\n", PREFIX_DUMPFNAME);
	return 0;
}

SSL_CTX* server_sslctx_init()
{
    	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	if (SSL_CTX_use_certificate_file(ctx, SERVER_CERTFNAME, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_PKEYFNAME, SSL_FILETYPE_PEM) <= 0 ) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	return ctx;
}

void cb_readfromvalidator(void *args)
{
	user_epolldata_t *udata = args;
	int sockfd = udata->eventfd;
	session_ctx_t *ctx = udata->ctx;

	unsigned char rcode;
	int ret, clientfd;
	hidns_update_msg reply;
	hidns_update_command *cmd;
	unsigned short reqid, replyid;

	debugInfo("cb_readfromvalidator is called.\n");
	ret = verify_hidns_getresult(sockfd, &replyid);
	cmd = session_cmdlist_pop(ctx, sockfd, &reqid);
	if (cmd == NULL || reqid != replyid)
	{
		// error
		perror("verify_hidns_getresult or session_cmdlist_pop error");
		rcode = RCODE_SERVER_ERROR;
		goto error_out;
	}
	if (ret != 0)
	{
		// error
		debugInfo("validator reply code=%u\n", ret);
		rcode = RCODE_UNAUTH_PREFIX;
		goto error_out;
	}
	// ok add to queue
	rr_update_cmd_t *ucmd = updatecmd_new();
	if ((updatecmd_init(ucmd, cmd, ctx)) != 0)
	{
		// error
		updatecmd_free(ucmd);
		rcode = RCODE_INVALID_PACKET;
		goto error_out;
	}
	rr_update_job_t *ujob = updatejob_new();
	updatejob_add_cmd(ujob, ucmd);
	workqueue_add_job(&JobQueue, ujob);
	debugInfo("cb_readfromvalidator add job to workqueue.\n");

	epoll_ctl(udata->epollfd, EPOLL_CTL_DEL, udata->eventfd, NULL);
	free(udata);
	return;

error_out:
	// respond and free
	debugInfo("cb_readfromvalidator: invalid message[%u].\n", rcode);
	clientfd = ctx->clientfd;
	updatemsg_init(&reply);
	if (cmd != NULL) {
		updatemsg_append_command(&reply, cmd);
		updatemsg_free_command(cmd);
	}		
	updatemsg_set_rcode(&reply, rcode);
	ret = session_writen(ctx, reply.rawbuf, reply.rawbuflen);
	if (ret == 0)
	{
		perror("send reply");
	}
	epoll_ctl(udata->epollfd, EPOLL_CTL_DEL, udata->eventfd, NULL);
	free(udata);
	return;
}

void cb_nsupdaterecv(void *args)
{
	user_epolldata_t *udata = args;
	int sockfd = udata->eventfd;
	rr_update_job_t *job = udata->ctx;
	rr_update_job_t *joblist = NULL, *jobptr = NULL;
	rr_update_cmd_t *ucmd = job->cmdbatch;
	pid_t pid = job->pid;
	int ret, status, i, len;
	struct itimerspec timerstop = {};
	memset(&timerstop, 0, sizeof(timerstop));

	hidns_update_msg reply;
	unsigned char rcode = RCODE_SERVER_ERROR;

	uint64_t exp;
	ret = read(sockfd, &exp, sizeof(uint64_t));
	debugInfo("cb_nsupdaterecv is called!\n");

	ret = waitpid(pid, &status, WNOHANG);
	if (ret == 0)
	{
		// havent finish
		perror("waitpid childprocess timeout");
		return;
	}
	if (ret != pid)
	{
		// error
		perror("waitpid");
		rcode = RCODE_SERVER_ERROR;
		goto error_out;
	}
	// else if (WIFEXITED(status))
	else
	{
		if (WEXITSTATUS(status) == 0)
		{
			// no error
			// reply all cmds
			debugInfo("update process done!\n");
			while (ucmd != NULL)
			{
				// insert to name tree here
				if (prefix_trienode_put(PrefixTrie, ucmd->cmd->rrprefixbuf, ucmd->cmd->rrprefixlen) != 0)
				{
					perror("prefix_trienode_put");
					// dump to log file
					exit(EXIT_FAILURE);
				}
				updatemsg_init(&reply);
				updatemsg_append_command(&reply, ucmd->cmd);
				// append signature and cert
				updatemsg_set_rcode(&reply, RCODE_OK);
				len = session_writen(ucmd->cmdctx, reply.rawbuf, reply.rawbuflen);
				if (len == 0) {
					perror("send reply");
				}
				// len = send(ucmd->cmdctx->clientfd, reply.rawbuf, reply.rawbuflen, 0);
				// if (len != reply.rawbuflen)
				// {
				// 	perror("send reply");
				// }
				debugInfo("cb_nsupdaterecv: reply ok.\n");
				ucmd = ucmd->next;
			}
			debugInfo("cb_nsupdaterecv reply done!\n");
			updatejob_free(job);
			if (prefix_trie_dump(PrefixTrie, PREFIX_DUMPFNAME) <= 0)
			{
				perror("prefix_trie_dump");
				// write to log file
				exit(EXIT_FAILURE);
			}
		}
		else if (job->cmdbatchsize == 1)
		{
			// error for a single cmd
			rcode = RCODE_SERVER_ERROR;
			goto error_out;
		}
		else
		{
			// error for cmdbatch, split and reinsert them
			debugInfo("cb_nsupdaterecv: split and retry the jobs.\n");
			ucmd = job->cmdbatch;
			while (ucmd != NULL)
			{
				++ucmd->retrycnt;
				ucmd = ucmd->next;
			}
			joblist = updatejob_split_job(job, 2);
			jobptr = joblist->next;
			joblist->prev = joblist->next = NULL;
			jobptr->prev = jobptr->next = NULL;
			workqueue_add_job(&JobQueue, joblist);
			workqueue_add_job(&JobQueue, jobptr);
		}

		epoll_ctl(udata->epollfd, EPOLL_CTL_DEL, udata->eventfd, NULL);
		timerfd_settime(udata->eventfd, 0, &timerstop, NULL);
		close(udata->eventfd);
		free(udata);
		return;
	}
error_out:
	debugInfo("cb_nsupdaterecv: reply error[%u].\n", rcode);
	updatemsg_init(&reply);
	updatemsg_append_command(&reply, ucmd->cmd);
	updatemsg_set_rcode(&reply, rcode);
	// len = send(ucmd->cmdctx->clientfd, reply.rawbuf, reply.rawbuflen, 0);
	// if (len != reply.rawbuflen)
	// {
	// 	perror("send reply");
	// }
	len = session_writen(ucmd->cmdctx, reply.rawbuf, reply.rawbuflen);
	if (len == 0) {
		perror("send reply");
	}
	updatejob_free(job);

	epoll_ctl(udata->epollfd, EPOLL_CTL_DEL, udata->eventfd, NULL);
	timerfd_settime(udata->eventfd, 0, &timerstop, NULL);
	close(udata->eventfd);
	free(udata);
	return;
}

void cb_readfromclient(void *args)
{
	user_epolldata_t *udata = args;
	session_ctx_t *ctx = udata->ctx;
	hidns_update_msg msg, reply;
	updatemsg_init(&reply);
	unsigned char rcode;
	unsigned short len;
	int ret, chk;

	debugInfo("cb_readfromclient is called.\n");
	// 1. Read length
	ret = session_readn(ctx, (void *)&msg.len_n, sizeof(msg.len_n));
	if (ret == 0)
	{
		// should close connect
		// TBD
		goto conn_close;
	}
	// else if (ret != sizeof(msg.len_n))
	// {
	// 	rcode = RCODE_INVALID_PACKET;
	// 	goto error_out;
	// }
	len = ntohs(msg.len_n);

	// 2. Read message
	ret = session_readn(ctx, msg.buf, len);
	if (ret == 0)
	{
		// should close connect
		// TBD
		goto conn_close;
	}
	// else if (ret != len)
	// {
	// 	rcode = RCODE_INVALID_PACKET;
	// 	goto error_out;
	// }

	// 3. Parse and check message
	if (updatemsg_parse(&msg) != 0)
	{
		perror("updatemsg_parse");
		rcode = RCODE_INVALID_PACKET;
		goto error_out;
	}
	debugInfo("cb_readfromclient recv %u Bytes\n", msg.rawbuflen);
	
	// FILE *f = fopen("cert.der", "wb");
	// fwrite(msg.cert.valbuf, 1, msg.cert.length, f);
	// fclose(f);

	chk = check_updatemsg_request(&msg);
	if (chk < 0)
	{
		perror("check_updatemsg_request");
		rcode = RCODE_INVALID_PACKET;
		goto error_out;
	}
	// printf("[1] %.*s", msg.cert.length, msg.cert.valbuf);

	hidns_update_command *cmd;
	int vrfd;
	unsigned short vrid;
	struct timeval tv;
	cmd = updatemsg_extract_command(&msg);
	// printf("[2] %.*s", msg.cert.length, msg.cert.valbuf);
	// check prefix here
	if (strlen(SERVER_PREFIX) > cmd->rrprefixlen || memcmp(SERVER_PREFIX, cmd->rrprefixbuf, strlen(SERVER_PREFIX)) != 0)
	{
		perror("check_rr_prefix");
		rcode = RCODE_UNAUTH_PREFIX;
		updatemsg_free_command(cmd);
		goto error_out;
	}
	vrfd = verify_open_udp_socket_nonblock("127.0.0.1", 5551);
	gettimeofday(&tv, NULL);
	vrid = tv.tv_usec && 0xffff;
	session_cmdlist_push(ctx, vrfd, vrid, cmd);

	// 4. Verify message
	struct epoll_event verifyev;
	user_epolldata_t *newudata;

	newudata = (user_epolldata_t *)malloc(sizeof(user_epolldata_t));
	newudata->eventfd = vrfd;
	newudata->epollfd = udata->epollfd;
	newudata->eventtype = 1;
	newudata->ctx = ctx;
	newudata->cb = cb_readfromvalidator;
	verifyev.events = EPOLLIN | EPOLLET;
	verifyev.data.ptr = (void *)newudata;
	if (epoll_ctl(udata->epollfd, EPOLL_CTL_ADD, vrfd, &verifyev) != 0) {
		perror("epoll_ctl_add_verifyfd");
		exit(EXIT_FAILURE);
	}
	
	if (chk == 0)
	{
		// only verify cert
		// printf("[5] %.*s", msg.cert.length, msg.cert.valbuf);
		ret = verify_hidns_x509_cert_send(vrfd, vrid, msg.cert.valbuf, msg.cert.length, VERIFY_REQ_ARGTYPE_CERT_DER);
		debugInfo("cb_readfromclient start to verify the certificate.\n");
	}
	else
	{
		// verify the command
		ret = verify_hidns_nocert_cmd_send(vrfd, vrid, msg._tbsptr, msg._tbslen, msg.sig.signerpfx, msg.sig.signerlen, msg.sig.signature, msg.sig.sigbuflen, msg.sig.algorithm);
		debugInfo("cb_readfromclient start to verify the command.\n");
	}

	if (ret == 0)
	{
		// done
		return;
	}
	debugInfo("cb_readfromclient failed to verify the message.\n");
	if (ret > 0)
	{
		rcode = RCODE_SERVER_ERROR;
	}
	else
	{
		rcode = RCODE_INVALID_PACKET;
	}
	updatemsg_append_command(&reply, cmd);
	cmd = session_cmdlist_pop(ctx, vrfd, &vrid);
	updatemsg_free_command(cmd);

	epoll_ctl(udata->epollfd, EPOLL_CTL_DEL, vrfd, NULL);
	free(newudata);
	close(vrfd);
error_out:
	updatemsg_set_rcode(&reply, rcode);
	len = send(ctx->clientfd, reply.rawbuf, reply.rawbuflen, 0);
	if (len != reply.rawbuflen)
	{
		perror("send reply");
	}
	return;
conn_close:
	debugInfo("cb_readfromclient detected the connection closed.\n");
	epoll_ctl(udata->epollfd, EPOLL_CTL_DEL, ctx->clientfd, NULL);
	session_close(ctx);
	free(udata);
	return;
}

void *eventloop_thread(void *arg)
{
	int epollfd = *(int *)arg;
	int nevent, i;
	struct epoll_event events[MAX_EPOLLSIZE];
	user_epolldata_t *udata;
	while (1)
	{
		nevent = epoll_wait(epollfd, events, MAX_EPOLLSIZE, EPOLL_TIMEOUT);
		if (nevent == -1)
		{
			perror("epoll_wait");
			goto error_out;
		}
		else if (nevent != 0)
		{
			debugInfo("eventloopthread: %d events\n", nevent);
		}

		for (i = 0; i < nevent; i++)
		{
			if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP)
			{
				perror("events ERR or HUP");
				continue;
				// goto error_out;
			}
			// process event
			udata = events[i].data.ptr;
			udata->cb(events[i].data.ptr);
		}
	}
error_out:
	pthread_exit(NULL);
}

void *nsupdater_thread(void *arg)
{
	int epollfd = *(int *)arg;
	rr_update_job_t *job, *jobs, *joblist, *jobtail;
	int period_us, remain_us, maxjobcnt, remainjobcnt, remaintime;
	int timerfd;
	pid_t pid;
	struct itimerspec timersetting;
	struct epoll_event updatereceiverev;
	user_epolldata_t *newudata;

	period_us = 20000;
	maxjobcnt = 16;
	timersetting.it_value.tv_sec = 0;
	timersetting.it_value.tv_nsec = 100000000; // timeout 100ms
	timersetting.it_interval.tv_sec = 0;
	timersetting.it_interval.tv_nsec = 10000000; // retry 10ms

	while (1)
	{
		joblist = workqueue_get_njobs(&JobQueue, maxjobcnt, period_us, &remainjobcnt, &remaintime);
		if (joblist == NULL)
		{
			continue;
		}

		jobtail = joblist;
		while (remainjobcnt != 0)
		{
			while (jobtail->next != NULL)
				jobtail = jobtail->next;
			jobs = workqueue_get_njobs(&JobQueue, remainjobcnt, remaintime, &remainjobcnt, &remaintime);
			jobtail->next = jobs;
		}

		job = updatejob_merge_jobs(joblist);
		pid = fork();
		if (pid > 0)
		{
			// add timeout event
			timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
			newudata = (user_epolldata_t *)malloc(sizeof(user_epolldata_t));
			newudata->eventfd = timerfd;
			newudata->epollfd = epollfd;
			newudata->eventtype = 2;
			job->pid = pid;
			newudata->ctx = (void *)job;
			newudata->cb = cb_nsupdaterecv;
			updatereceiverev.events = EPOLLIN | EPOLLET;
			updatereceiverev.data.ptr = (void *)newudata;
			if (epoll_ctl(epollfd, EPOLL_CTL_ADD, timerfd, &updatereceiverev) != 0)
			{
				perror("epoll_ctl_add_timerfd");
			}
			if (timerfd_settime(timerfd, 0, &timersetting, NULL) == -1)
			{
				perror("timerfd_settime");
				goto error_out;
			}
			debugInfo("set an update timeout.\n");
		}
		else if (pid == 0)
		{
			// call nsupdate
			debugInfo("issue a nsupdate.\n");
			int ret;
			char cmdbuf[4096];
			char *cmdptr = cmdbuf;
			cmdptr += sprintf(cmdptr, "echo -e '");
			
			ret = updatecmdlist_mkbuf(job->cmdbatch, cmdptr, 4048);
			if (ret < 0)
			{
				exit(EXIT_FAILURE);
			}
			
			cmdptr += ret;
			cmdptr += sprintf(cmdptr, "' | nsupdate -v");
			if (execlp("bash", "bash", "-c", cmdbuf, NULL) < 0)
			{
				perror("error on exec nsupdate");
				exit(EXIT_FAILURE);
			}
			exit(EXIT_SUCCESS);
		}
	}
error_out:
	pthread_exit(NULL);
}

int main()
{
	DebugType = DEBUG_PRINT;
	server_prefixtrie_init();
	SSL_CTX *sslctx = server_sslctx_init();

	workqueue_init(&JobQueue);

	int epollfd_listen, epollfd_event;
	pthread_t tid_evloop, tid_nsupdater;
	epollfd_listen = epoll_create(MAX_EPOLLSIZE);
	epollfd_event = epoll_create(MAX_EPOLLSIZE);
	pthread_create(&tid_evloop, NULL, eventloop_thread, &epollfd_event);
	pthread_create(&tid_nsupdater, NULL, nsupdater_thread, &epollfd_event);

	int listensockfd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(SERVER_PORT);
	addr.sin_addr.s_addr = inet_addr(SERVER_IP);
	if (bind(listensockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) < 0)
	{
		perror("bind");
		return 2;
	}
	if (listen(listensockfd, 5) < 0)
	{
		perror("listen");
		return 3;
	}
	ntySetNonblock(listensockfd);
	ntySetReUseAddr(listensockfd);

	int listensockfd_ssl = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr_ssl;
	memset(&addr_ssl, 0, sizeof(struct sockaddr_in));
	addr_ssl.sin_family = AF_INET;
	addr_ssl.sin_port = htons(SERVER_SSL_PORT);
	addr_ssl.sin_addr.s_addr = inet_addr(SERVER_IP);
	if (bind(listensockfd_ssl, (struct sockaddr *)&addr_ssl, sizeof(struct sockaddr_in)) < 0)
	{
		perror("bind_ssl");
		return 2;
	}
	if (listen(listensockfd_ssl, 5) < 0)
	{
		perror("listen_ssl");
		return 3;
	}
	ntySetNonblock(listensockfd_ssl);
	ntySetReUseAddr(listensockfd_ssl);

	struct epoll_event listenev;
	listenev.events = EPOLLIN | EPOLLET;
	listenev.data.fd = listensockfd;
	epoll_ctl(epollfd_listen, EPOLL_CTL_ADD, listensockfd, &listenev);
	debugInfo("add listener to epollfd_listen!\n");

	struct epoll_event listenev_ssl;
	listenev_ssl.events = EPOLLIN | EPOLLET;
	listenev_ssl.data.fd = listensockfd;
	epoll_ctl(epollfd_listen, EPOLL_CTL_ADD, listensockfd_ssl, &listenev_ssl);
	debugInfo("add ssl listener to epollfd_listen!\n");

	int nevent, i, clientfd;
	struct epoll_event events[3];
	// struct sockaddr_in client_addr;
	// socklen_t client_len;
	session_ctx_t *ctx;
	user_epolldata_t *udata;
	struct epoll_event clientrwev;

	while (1)
	{
		nevent = epoll_wait(epollfd_listen, events, 3, EPOLL_TIMEOUT);
		if (nevent == -1)
		{
			perror("epoll_wait");
			goto error_out;
		}
		else if (nevent != 0)
		{
			debugInfo("listenthread: %d events\n", nevent);
		}
		for (i = 0; i < nevent; i++)
		{
			// process
			if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP)
			{
				fprintf(stderr, "events ERR or HUP!\n");
				goto error_out;
			}
			if (events[i].data.fd == listensockfd_ssl) {
				ctx = session_accept(events[i].data.fd, sslctx);
			} else {
				ctx = session_accept(events[i].data.fd, NULL);
			}
			if (ctx == NULL) {
				perror("session_accept");
				continue;
			}
			// memset(&client_addr, 0, sizeof(struct sockaddr_in));
			// client_len = sizeof(client_addr);

			// clientfd = accept(events[i].data.fd, (struct sockaddr *)&client_addr, &client_len);
			// if (clientfd < 0)
			// {
			// 	perror("accept");
			// 	return -1;
			// }

			// ctx = (session_ctx_t *)malloc(sizeof(session_ctx_t));
			// ctx->clientfd = clientfd;
			// ctx->cmdbuf = NULL;
			// ctx->ssl = NULL; // TBD

			udata = (user_epolldata_t *)malloc(sizeof(user_epolldata_t));
			udata->eventfd = clientfd;
			udata->epollfd = epollfd_event;
			udata->eventtype = 0;
			udata->ctx = (void *)ctx;
			udata->cb = cb_readfromclient;

			clientrwev.events = EPOLLIN | EPOLLET;
			clientrwev.data.ptr = (void *)udata;

			if (epoll_ctl(epollfd_event, EPOLL_CTL_ADD, clientfd, &clientrwev) != 0)
			{
				perror("epoll_ctl_add_clientfd");
			}
		}
	}
error_out:
	close(listensockfd);
	close(listensockfd_ssl);
	pthread_join(tid_evloop, NULL);
	pthread_join(tid_nsupdater, NULL);
	return 0;
}

