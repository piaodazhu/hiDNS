#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <pthread.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/wait.h>

#include "eventcontext.h"
#include "updatemsgtools.h"
#include "verifystruct.h"
#include "workqueue.h"
#include "ins_verifyasync.h"

#define SERVER_PORT		1038
#define SERVER_IP		"127.0.0.1"
#define MAX_EPOLLSIZE		1000
#define MAX_BUFSIZE		4096
#define EPOLL_TIMEOUT		2000
#define TIME_SUB_MS(tv1, tv2)  ((tv1.tv_sec - tv2.tv_sec) * 1000 + (tv1.tv_usec - tv2.tv_usec) / 1000)


workqueue_t JobQueue;

static int ntySetNonblock(int fd) {
	int flags;
	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) return flags;
	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) < 0) return -1;
	return 0;
}

static int ntySetReUseAddr(int fd) {
	int reuse = 1;
	return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse));
}

void cb_readfromvalidator(void* args)
{
	user_epolldata_t *udata = args;
	int sockfd = udata->eventfd;
	session_ctx_t* ctx = udata->ctx;

	unsigned char rcode;
	int ret, clientfd;
	hidns_update_command *cmd;
	unsigned short reqid, replyid;
	ret = verify_hidns_getresult(sockfd, &replyid);
	cmd = session_cmdlist_pop(ctx, sockfd, &reqid);
	if (cmd == NULL || reqid != replyid) {
		// error
		perror("verify_hidns_getresult or session_cmdlist_pop error");
		rcode = RCODE_SERVER_ERROR;
		goto error_out;
	}
	if (ret != 0) {
		// error
		rcode = RCODE_UNAUTH_PREFIX;
		goto error_out;
	}
	// ok add to queue
	rr_update_cmd_t *ucmd = updatecmd_new();
	if ((updatecmd_init(ucmd, cmd, ctx))!=0) {
		// error
		updatecmd_free(ucmd);
		rcode = RCODE_INVALID_PACKET;
		goto error_out;
	}
	rr_update_job_t *ujob = updatejob_new();
	updatejob_add_cmd(ujob, ucmd);
	workqueue_add_job(&JobQueue, ujob);
	
	epoll_ctl(udata->epollfd, EPOLL_CTL_DEL, udata->eventfd, NULL);
	free(udata);
	return;

error_out:
	// respond and free
	hidns_update_msg reply;
	clientfd = ((session_ctx_t*)(udata->ctx))->clientfd;
	updatemsg_init(&reply);
	if (cmd != NULL)
		updatemsg_append_command(&reply, cmd);
	updatemsg_set_rcode(&reply, rcode);
	ret = send(clientfd, reply.rawbuf, reply.rawbuflen, 0);
	if (ret != reply.rawbuflen) {
		perror("send reply");
	}

	epoll_ctl(udata->epollfd, EPOLL_CTL_DEL, udata->eventfd, NULL);
	free(udata);
	return;
}

void cb_nsupdaterecv(void* args)
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
	unsigned char rcode;

	uint64_t exp;
	int ret = read(sockfd, &exp, sizeof(uint64_t));
	printf("cb_nsupdaterecv is called!\n");

	ret = waitpid(pid, &status, WNOHANG);
	if (ret == 0) {
		// havent finish
		perror("waitpid childprocess timeout");
		return;
	}
	if (ret != pid) {
		// error
		perror("waitpid");
		rcode = RCODE_SERVER_ERROR;
		goto error_out;
	}
	else if (WIFEXITED(status)) {	
		if (WEXITSTATUS(status) == 0) {
			// no error
			// reply all cmds
			while (ucmd != NULL) {
				updatemsg_init(&reply);
				updatemsg_append_command(&reply, ucmd->cmd);
				// append signature and cert
				updatemsg_set_rcode(&reply, RCODE_OK);
				len = send(ucmd->cmdctx->clientfd, reply.rawbuf, reply.rawbuflen, 0);
				if (len != reply.rawbuflen) {
					perror("send reply");
				}
				ucmd = ucmd->next;
			}
			updatejob_free(job);
		}
		else if (job->cmdbatchsize == 1) {
			// error for a single cmd
			rcode = RCODE_SERVER_ERROR;
			goto error_out;
		}
		else {
			// error for cmdbatch, split and reinsert them
			ucmd = job->cmdbatch;
			while (ucmd != NULL) {
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
	updatemsg_init(&reply);
	updatemsg_append_command(&reply, ucmd->cmd);
	updatemsg_set_rcode(&reply, rcode);
	len = send(ucmd->cmdctx->clientfd, reply.rawbuf, reply.rawbuflen, 0);
	if (len != reply.rawbuflen) {
		perror("send reply");
	}
	updatejob_free(job);

	epoll_ctl(udata->epollfd, EPOLL_CTL_DEL, udata->eventfd, NULL);
	timerfd_settime(udata->eventfd, 0, &timerstop, NULL);
	close(udata->eventfd);
	free(udata);
	return;
}

void cb_readfromclient(void* args)
{
	user_epolldata_t *udata = args;
	int sockfd = udata->eventfd;
	session_ctx_t* ctx = udata->ctx;
	hidns_update_msg msg, reply;
	updatemsg_init(&reply);
	unsigned char rcode;
	unsigned short len;
	int ret, chk;
	ret = recv(sockfd, (void*)msg.len_n, sizeof(msg.len_n), 0);
	if (ret <= 0) {
		// should close connect
		// TBD
		goto conn_close;
	}
	else if (ret != sizeof(msg.len_n)) {
		rcode = RCODE_INVALID_PACKET;
		goto error_out;
	}
	len = ntohs(msg.len_n);
	ret = recv(sockfd, msg.buf, len, 0);
	if (ret < 0) {
		// should close connect
		// TBD
		goto conn_close;
	}
	if (ret != len) {
		rcode = RCODE_INVALID_PACKET;
		goto error_out;
	}

	// parse
	if (updatemsg_parse(&msg) != 0) {
		perror("updatemsg_parse");
		rcode = RCODE_INVALID_PACKET;
		goto error_out;
	}
	printf("cb_readfromclient recv :: %u Bytes\n", msg.rawbuflen);

	chk = check_updatemsg_request(&msg);
	if (chk < 0) {
		perror("check_updatemsg_request");
		rcode = RCODE_INVALID_PACKET;
		goto error_out;
	}

	hidns_update_command *cmd;
	int vrfd;
	unsigned short vrid;
	struct timeval tv;
	cmd = updatemsg_extract_command(&msg);
	vrfd = verify_open_udp_socket_nonblock("127.0.0.1", 5551);
	gettimeofday(&tv, NULL);
	vrid = tv.tv_usec && 0xffff;
	session_cmdlist_push(ctx, vrfd, vrid, cmd);

	// add epoll event
	struct epoll_event verifyev;
	user_epolldata_t *newudata;
	
	newudata = (user_epolldata_t*) malloc(sizeof(user_epolldata_t));	
	newudata->eventfd = vrfd;
	newudata->epollfd = udata->epollfd;
	newudata->eventtype = 1;
	newudata->ctx = ctx;
	newudata->cb = cb_readfromvalidator;
	verifyev.events = EPOLLIN | EPOLLET;
	verifyev.data.ptr = (void*)newudata;
	epoll_ctl(udata->epollfd, EPOLL_CTL_ADD, vrfd, &verifyev);

	if (chk == 0) {
		// only verify cert
		ret = verify_hidns_x509_cert_send(vrfd, vrid, msg.cert.valbuf, msg.cert.length, VERIFY_REQ_ARGTYPE_CERT_DER);
	} else {
		// verify the command
		ret = verify_hidns_nocert_cmd_send(vrfd, vrid, msg._tbsptr, msg._tbslen, msg.sig.signerpfx, msg.sig.signerlen, msg.sig.signature, msg.sig.sigbuflen, msg.sig.algorithm);
	}
	if (ret == 0) {
		// done
		return;
	}
	if (ret > 0) {
		rcode = RCODE_SERVER_ERROR;
	}
	else {
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
	len = send(sockfd, reply.rawbuf, reply.rawbuflen, 0);
	if (len != reply.rawbuflen) {
		perror("send reply");
	}
	return;
conn_close:
	epoll_ctl(udata->epollfd, EPOLL_CTL_DEL, sockfd, NULL);
	close(sockfd);
	free(udata);
	session_cmdlist_t *p, *q;
	p = ctx->cmdbuf;
	while (p) {
		q = p;
		p = p->next;
		free(q);
	}
	free(ctx);
	return;
}

void* event_processing_thread(void *arg)
{
	int epollfd = *(int*)arg;
	int nevent, i;
	struct epoll_event events[MAX_EPOLLSIZE];
	user_epolldata_t* udata;
	while (1) {
		nevent = epoll_wait(epollfd, events, MAX_EPOLLSIZE, EPOLL_TIMEOUT);
		if (nevent == -1) {
			perror("epoll_wait");
			goto error_out;
		}
		if (nevent == 0) {
			printf("thread1 no event!\n");
		}

		printf("thread1 %d event!\n", nevent);
		for (i = 0; i < nevent; i++) {
			if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP)
			{
				perror("events ERR or HUP");
				goto error_out;
			}
			// process event
			printf("thread1 start process!\n");
			udata = events[i].data.ptr;
			udata->cb(events[i].data.ptr);
		}	
	}
error_out:
	pthread_exit(NULL);
}

void* nsupdate_caller_thread(void *arg)
{
	int epollfd = *(int*)arg;
	rr_update_job_t *job, *jobs, *joblist, *jobtail;
	int period_us, remain_us, maxjobcnt, remainjobcnt, remaintime;
	int timerfd;
	pid_t pid;
	struct itimerspec timersetting;
	struct epoll_event updatereceiverev;
	user_epolldata_t *newudata;

	period_us = 20000;
	maxjobcnt = 16;
	timersetting.it_value.tv_sec  = 0;
	timersetting.it_value.tv_nsec = 100000000;	// timeout 100ms
	timersetting.it_interval.tv_sec  = 0;
	timersetting.it_interval.tv_nsec = 10000000;	// retry 10ms
	

	while (1)
	{
		joblist = workqueue_get_njobs(&JobQueue, maxjobcnt, period_us, &remainjobcnt, &remaintime);
		if (joblist == NULL) {
			continue;
		}
		
		jobtail = joblist;
		while (remainjobcnt != 0) {
			while (jobtail->next != NULL) jobtail = jobtail->next;
			jobs = workqueue_get_njobs(&JobQueue, remainjobcnt, remaintime, &remainjobcnt, &remaintime);
			jobtail->next = jobs;
		}

		job = updatejob_merge_jobs(joblist);
		pid = fork();
		if (pid > 0) {
			// add timeout event
			timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
			newudata = (user_epolldata_t*)malloc(sizeof(user_epolldata_t));
			newudata->eventfd = timerfd;
			newudata->epollfd = epollfd;
			newudata->eventtype = 2;
			job->pid = pid;
			newudata->ctx = (void*)job;
			newudata->cb = cb_nsupdaterecv;
			updatereceiverev.events = EPOLLIN | EPOLLET;
			updatereceiverev.data.ptr = (void*)newudata;
			epoll_ctl(epollfd, EPOLL_CTL_ADD, timerfd, &updatereceiverev);
			if (timerfd_settime(timerfd, 0, &timersetting, NULL) == -1)
			{
				perror("timerfd_settime");
				goto error_out;
			}
		}
		else if (pid == 0) {
			// call nsupdate
			int ret;
			char cmdbuf[4096];
			char *cmdptr = cmdbuf;
			cmdptr += sprintf(cmdptr, "echo -e '");
			
			ret = updatecmdlist_mkbuf(job->cmdbatch, cmdptr, 4048);
			if (ret < 0) {
				exit(-1);
			}
			cmdptr += ret;
			cmdptr += sprintf(cmdptr, "' | nsupdate -v");

			if (execlp("bash", "bash", "-c", cmdbuf, NULL) < 0 ) {  
				perror("error on exec nsupdate");  
				exit(-1);
			}
			exit(-1);
		}
	}
error_out:
	pthread_exit(NULL);
}

int main()
{
	workqueue_init(&JobQueue);

	int epollfd_listen, epollfd_rw;
	pthread_t tid_rw, tid_nsupdate;
	epollfd_listen = epoll_create(MAX_EPOLLSIZE);
	epollfd_rw = epoll_create(MAX_EPOLLSIZE);
	pthread_create(&tid_rw, NULL, event_processing_thread, &epollfd_rw);
	pthread_create(&tid_nsupdate, NULL, nsupdate_caller_thread, &epollfd_rw);

	int listensockfd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(1038);
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	if (bind(listensockfd, (struct sockaddr*)&addr, sizeof(struct sockaddr_in)) < 0) {
		perror("bind");
		return 2;
	}
	if (listen(listensockfd, 5) < 0) {
		perror("listen");
		return 3;
	}
	ntySetNonblock(listensockfd);
	ntySetReUseAddr(listensockfd);

	struct epoll_event listenev; 
	listenev.events = EPOLLIN | EPOLLET;
	listenev.data.fd = listensockfd;
	epoll_ctl(epollfd_listen, EPOLL_CTL_ADD, listensockfd, &listenev);
	printf("add event to epollfd_listen!\n");

	int nevent, i, clientfd;
	struct epoll_event events[3];
	struct sockaddr_in client_addr;
	socklen_t client_len;
	session_ctx_t *ctx;
	user_epolldata_t *udata;
	struct epoll_event clientrwev;

	while (1) {
		nevent = epoll_wait(epollfd_listen, events, 3, EPOLL_TIMEOUT);
		for (i = 0; i < nevent; i++) {
			// process
			if(events[i].events & EPOLLERR || events[i].events & EPOLLHUP)
			{
				fprintf(stderr, "events ERR or HUP!\n");
				goto error_out;
			}
			printf("thread0 start process!\n");
			
			memset(&client_addr, 0, sizeof(struct sockaddr_in));
			client_len = sizeof(client_addr);
			
			clientfd = accept(events[i].data.fd, (struct sockaddr*)&client_addr, &client_len);
			if (clientfd < 0) {
				perror("accept");
				return -1;
			}
			
			ctx = (session_ctx_t*)malloc(sizeof(session_ctx_t));
			ctx->clientfd = clientfd;
			ctx->cmdbuf = NULL;
			ctx->ssl = NULL; // TBD
			ctx->state = 0;

			udata = (user_epolldata_t*)malloc(sizeof(user_epolldata_t));
			udata->eventfd = clientfd;
			udata->epollfd = epollfd_rw;
			udata->eventtype = 0;
			udata->ctx = (void*)ctx;
			udata->cb = cb_readfromclient;

			clientrwev.events = EPOLLIN | EPOLLET;
			clientrwev.data.ptr = (void*)udata;

			epoll_ctl(epollfd_rw, EPOLL_CTL_ADD, clientfd, &clientrwev);
			printf("add client rw event to epollfd_rw!\n");
		}
	}
error_out:
	close(listensockfd);
	pthread_join(tid_rw, NULL);
	pthread_join(tid_nsupdate, NULL);
	return 0;
}
