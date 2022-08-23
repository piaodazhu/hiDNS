#include <time.h>
#include <sys/time.h>
#include "workqueue.h"

#define INS_PFXMAXSIZE 256
int
insprefix_prefix2domainname(const char* prefix, int plen, char* domainname, int dlen)
{
	if (*prefix != '/') return -1;
	if (plen >= INS_PFXMAXSIZE) return -1;
	if (prefix[plen - 1] == '/') --plen;
	if (plen > dlen) return -1;
	char buf[INS_PFXMAXSIZE];
	char *reverse_ptr = buf + INS_PFXMAXSIZE;
	int idx = 1;
	int pre_splash = 0;
	int clen = 0;
	int cnum = 0;
	while (idx < plen) {
		if (prefix[idx] == '/') {
			clen = idx - pre_splash - 1;
			++cnum;
			if (clen > 63) return -1;
			if (cnum > 8) return -1;
			// if (clen == 0) return CHECKPREFIX_EMPTY_COMPONENT;
			*(--reverse_ptr) = '.';
			reverse_ptr -= clen;
			memcpy(reverse_ptr, prefix + pre_splash + 1, clen);
			pre_splash = idx;
		} else if (!((prefix[idx] >= '0' && prefix[idx] <= '9')
					 || (prefix[idx] >= 'a' && prefix[idx] <= 'z') 
					 || prefix[idx] == '-')) {
			return -1;
		}
		idx++;
	}
	clen = idx - pre_splash - 1;
	*(--reverse_ptr) = '.';
	reverse_ptr -= clen;
	memcpy(reverse_ptr, prefix + pre_splash + 1, clen);
	memcpy(domainname, reverse_ptr, plen);
	domainname[plen] = 0;
	return plen;
}

rr_update_cmd_t*
updatecmd_new()
{
	rr_update_cmd_t *cmd = (rr_update_cmd_t*) malloc(sizeof(rr_update_cmd_t));
	cmd->cmd = NULL;
	cmd->cmdctx = NULL;
	cmd->nsupdatebuf = NULL;
	cmd->prev = NULL;
	cmd->next = NULL;
	return cmd;
}

void
updatecmd_free(rr_update_cmd_t *cmd)
{
	if (cmd->cmd)
		updatemsg_free_command(cmd->cmd);
	if (cmd->nsupdatebuf)
		free(cmd->nsupdatebuf);
	free(cmd);
}

int
updatecmd_init(rr_update_cmd_t *cmd, hidns_update_command *c, session_ctx_t *cmdctx)
{
	// make command. only add and del now
	int ret;
	char *op, *type;
	char dname[INS_PFXMAXSIZE];
	char cmdbuf[2048];
	switch (c->opcode) {
	case COMMAND_OPCODE_ADDRR: op = "update add"; break;
	case COMMAND_OPCODE_DELRR: op = "update del"; break;
	case COMMAND_OPCODE_PUTSIG: op = "update add"; break;
	default: return -1;
	}
	switch (c->rrtype) {
	case COMMAND_RRTYPE_A: type = "A"; break;
	case COMMAND_RRTYPE_NS: type = "NS"; break;
	case COMMAND_RRTYPE_TXT: type = "TXT"; break;
	case COMMAND_RRTYPE_CERT: type = "CERT"; break;
	case COMMAND_RRTYPE_HSIG:type = "TXT"; break;
	default: return -2;
	}
	ret = insprefix_prefix2domainname(c->rrprefixbuf, c->rrprefixlen, dname, INS_PFXMAXSIZE);
	if (ret <= 0) return -3;
	ret = snprintf(cmdbuf, 2048, "%s %s %u %s %.*s\n", op, dname, c->rrttl, type, c->rrvaluelen, c->rrvaluebuf);
	if (ret <= 0) return -4;
	
	// initialization no error
	if (cmd->cmd)
		updatemsg_free_command(cmd->cmd);
	if (cmd->nsupdatebuf)
		free(cmd->nsupdatebuf);
	cmd->nsupdatebuflen = ret;
	cmd->nsupdatebuf = malloc(ret);
	memcpy(cmd->nsupdatebuf, cmdbuf, ret);
	
	cmd->cmdstate = 0;
	cmd->retrycnt = 0;
	cmd->cmd = c;
	cmd->cmdctx = cmdctx;
	return 0;
}

int updatecmdlist_mkbuf(const rr_update_cmd_t *cmd, unsigned char* buf, int buflen)
{
	int totlen, curidx = 0;
	totlen = 32;
	const rr_update_cmd_t *p;
	p = cmd;
	while (p != NULL && totlen < buflen) {
		totlen += p->nsupdatebuflen;
		p = p->next;
	}
	if (totlen >= buflen) {
		return -1;
	}
	
	// get server IP from the prefix configuration!
	char* serverip = "127.0.0.1";
	char startline[32];
	char* endline = "send\n";
	int len = snprintf(startline, 32, "server %s\n", serverip);
	memcpy(buf + curidx, startline, len);
	curidx += len;
	p = cmd;
	while (p != NULL) {
		memcpy(buf + curidx, p->nsupdatebuf, p->nsupdatebuflen);
		curidx += p->nsupdatebuflen;
		p = p->next;
	}
	memcpy(buf + curidx, endline, strlen(endline));
	curidx += strlen(endline);
	return curidx;
}

rr_update_job_t*
updatejob_new()
{
	rr_update_job_t *job = (rr_update_job_t*) malloc(sizeof(rr_update_job_t));
	job->state = 0;
	job->pid = 0;
	job->cmdbatchsize = 0;
	job->cmdbatch = NULL;
	job->prev = NULL;
	job->next = NULL;
	return job;
}


void
updatejob_free(rr_update_job_t *job)
{
	updatejob_clear(job);
	free(job);
}


void
updatejob_init(rr_update_job_t* job)
{
	job->state = 0;
	job->pid = 0;
	job->cmdbatchsize = 0;
	job->cmdbatch = NULL;
	job->prev = NULL;
	job->next = NULL;
}


void
updatejob_clear(rr_update_job_t *job)
{
	job->state = 0;
	job->cmdbatch = 0;
	if (job->cmdbatch != NULL) {
		rr_update_cmd_t *p, *q;
		p = job->cmdbatch;
		while (p != NULL) {
			q = p->next;
			updatecmd_free(p);
			p = q;
		}
	}
}


int
updatejob_add_cmd(rr_update_job_t *job, rr_update_cmd_t *cmd)
{
	job->cmdbatchsize++;
	LL_ADD(cmd, job->cmdbatch);
	return 0;
}


rr_update_job_t*
updatejob_merge_jobs(rr_update_job_t *joblist)
{
	if (joblist == NULL || joblist->next == NULL) return joblist;
	joblist->state = 1;
	rr_update_job_t *jobptr, *tmp;
	rr_update_cmd_t *cmdptr;
	jobptr = joblist->next;
	cmdptr = joblist->cmdbatch;
	while (cmdptr->next != NULL) {
		cmdptr = cmdptr->next;
	}

	while (jobptr != NULL) {
		joblist->cmdbatchsize += jobptr->cmdbatchsize;
		cmdptr->next = jobptr->cmdbatch;
		jobptr->cmdbatch->prev = cmdptr;
		while (cmdptr->next != NULL) cmdptr = cmdptr->next;
		tmp = jobptr;
		jobptr = jobptr->next;
		free(tmp);
	}
	joblist->next = NULL;
	joblist->prev = NULL;
	return joblist;
}


rr_update_job_t*
updatejob_split_job(rr_update_job_t *job_in, int factor)
{
	if (job_in == NULL || job_in->next != NULL) return NULL;
	if (job_in->cmdbatchsize == 1) return job_in;

	if (factor == 0) factor = job_in->cmdbatchsize;
	int maxsize = job_in->cmdbatchsize / factor;
	if (job_in->cmdbatchsize % factor) ++maxsize;
	printf("maxsize=%d\n", maxsize);
	int i, j, ret, idx, tot, len;
	rr_update_job_t *jobptr;
	rr_update_cmd_t  *cmdptr;
	jobptr = job_in;
	cmdptr = job_in->cmdbatch;
	idx = maxsize;
	tot = job_in->cmdbatchsize;
	for (i = 0; i < maxsize; i++) {
		cmdptr = cmdptr->next;
	}
	cmdptr->prev->next = NULL;
	jobptr->cmdbatchsize = maxsize;
	jobptr->state = 2;

	for (i = 1; i < factor; i++) {
		jobptr->next = updatejob_new();
		jobptr->next->prev = jobptr;
		jobptr = jobptr->next;

		jobptr->state = 2;
		len = MIN((tot - idx), maxsize);
		jobptr->cmdbatchsize = len;
		idx += len;
		jobptr->cmdbatch = cmdptr;
		for (j = 0; j < len; j++) cmdptr = cmdptr->next;
		if (cmdptr != NULL)
			cmdptr->prev->next = NULL;
	}
	return job_in;
}

workqueue_t*
workqueue_new()
{
	workqueue_t *wq = (workqueue_t*) malloc(sizeof(workqueue_t));
	wq->jobs_list = NULL;
	pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
	memcpy(&wq->jobs_mutex, &mutex, sizeof(wq->jobs_mutex));	
	memcpy(&wq->jobs_cond, &cond, sizeof(wq->jobs_cond));
	return wq;
}


void
workqueue_free(workqueue_t *wq)
{
	if (wq->jobs_list != NULL)
		workqueue_clear(wq);
	free(wq);
}


void
workqueue_init(workqueue_t* wq)
{
	if (wq == NULL) return;
	if (wq->jobs_list)
		workqueue_clear(wq);
	pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
	memcpy(&wq->jobs_mutex, &mutex, sizeof(wq->jobs_mutex));	
	memcpy(&wq->jobs_cond, &cond, sizeof(wq->jobs_cond));
}


void workqueue_clear(workqueue_t *wq)
{
	pthread_mutex_lock(&wq->jobs_mutex);	
	rr_update_job_t *pre, *ptr;
	ptr = wq->jobs_list;
	while (ptr != NULL) {
		pre = ptr;
		ptr = ptr->next;
		updatejob_free(pre);
	}
	wq->jobs_list = NULL;
	pthread_cond_broadcast(&wq->jobs_cond);	
	pthread_mutex_unlock(&wq->jobs_mutex);
}


int workqueue_add_job(workqueue_t *wq, rr_update_job_t *job)
{
	pthread_mutex_lock(&wq->jobs_mutex);	
	// printf("add job...\n");
	LL_ADD(job, wq->jobs_list);
	wq->statistics++;
	pthread_cond_signal(&wq->jobs_cond);	
	pthread_mutex_unlock(&wq->jobs_mutex);
}


rr_update_job_t* workqueue_get_job(workqueue_t *wq)
{
	rr_update_job_t *job = NULL;
	pthread_mutex_lock(&wq->jobs_mutex);
	// printf("get job...\n");
	while (wq->jobs_list == NULL) {
		// printf("cond wait...\n");
		pthread_cond_wait(&wq->jobs_cond, &wq->jobs_mutex);
	}
	job = wq->jobs_list;
	// printf("-- %d --\n", job->pid);
	while (job->next != NULL) job = job->next;

	// printf("before remove: ");
	// rr_update_job_t *ptr = wq->jobs_list;
	// while (ptr != NULL) {
	// 	printf("%d ", ptr->pid);
	// 	ptr = ptr->next;
	// }

	// ptr = job->prev;
	// printf("delete %d ...\n", job->pid);
	// printf("-- %p --\n", job->next);
	LL_REMOVE(job, wq->jobs_list);
	// printf("-- %d --\n", ptr->pid);
	// printf("-- %p --\n", ptr->next);

	// printf("\nafter remove: ");
	// ptr = wq->jobs_list;
	// while (ptr != NULL) {
	// 	printf("%d ", ptr->pid);
	// 	ptr = ptr->next;
	// }
	// printf("\n");

	pthread_mutex_unlock(&wq->jobs_mutex);
	return job;
}


rr_update_job_t* workqueue_get_joblist(workqueue_t *wq, int totalcmdbuflen)
{
	rr_update_job_t *srcptr, *srctmp;
	rr_update_job_t *dstptr, *dsthead;
	int curlen = 32;
	pthread_mutex_lock(&wq->jobs_mutex);
	while (wq->jobs_list == NULL) {
		pthread_cond_wait(&wq->jobs_cond, &wq->jobs_mutex);
	}
	srctmp = wq->jobs_list;
	while (srctmp->next != NULL) srctmp = srctmp->next;
	srcptr = srctmp->prev;
	LL_REMOVE(srctmp, wq->jobs_list);
	dsthead = srctmp;
	dstptr = srctmp;
	if (dsthead->state == 0) {
		while (srcptr != NULL && srcptr->state == 0 && srcptr->cmdbatch->nsupdatebuflen + curlen <= totalcmdbuflen) {
			curlen += srcptr->cmdbatch->nsupdatebuflen;
			srctmp = srcptr;
			srcptr = srcptr->prev;
			LL_REMOVE(srctmp, wq->jobs_list);
			dstptr->next = srctmp;
			srctmp->prev = dstptr;
			dstptr = dstptr->next;
		}
	}
	pthread_mutex_unlock(&wq->jobs_mutex);
	return dsthead;
}

rr_update_job_t* workqueue_get_njobs(workqueue_t *wq, int maxjobcnt, int timeout_us, int *remainjobcnt, int *remaintime_us)
{
	rr_update_job_t *srcptr, *srctmp;
	rr_update_job_t *dstptr, *dsthead;
	
	struct timespec now, timeout;
	long t;
	clock_gettime(CLOCK_MONOTONIC, &now);
	timeout.tv_sec = now.tv_sec + (now.tv_nsec + timeout_us * 1000) / 1000000000;
	timeout.tv_nsec = (now.tv_nsec + timeout_us * 1000) % 1000000000;

	int jobcnt = 0, ret = 0;
	*remainjobcnt = 0;	// 0 means finish
	*remaintime_us = 0;
	pthread_mutex_lock(&wq->jobs_mutex);
	while (wq->jobs_list == NULL) {
		// pthread_cond_wait(&wq->jobs_cond, &wq->jobs_mutex);
		ret = pthread_cond_timedwait(&wq->jobs_cond, &wq->jobs_mutex, &timeout);
		if (ret != 0) {
			pthread_mutex_unlock(&wq->jobs_mutex);
			return NULL;
		}
	}
	srctmp = wq->jobs_list;
	while (srctmp->next != NULL) srctmp = srctmp->next;
	srcptr = srctmp->prev;
	LL_REMOVE(srctmp, wq->jobs_list);
	dsthead = srctmp;
	dstptr = srctmp;
	++jobcnt;

	if (dsthead->state == 0) {
		while (srcptr != NULL && srcptr->state == 0 && jobcnt < maxjobcnt) {
			++jobcnt;
			srctmp = srcptr;
			srcptr = srcptr->prev;
			LL_REMOVE(srctmp, wq->jobs_list);
			dstptr->next = srctmp;
			srctmp->prev = dstptr;
			dstptr = dstptr->next;
		}
		if (srcptr == NULL && jobcnt < maxjobcnt) {
			clock_gettime(CLOCK_MONOTONIC, &timeout);
			t = (timeout.tv_nsec - now.tv_nsec) / 1000 + (timeout.tv_sec - now.tv_sec) * 1000000;
			*remainjobcnt = maxjobcnt - jobcnt;
			*remaintime_us = timeout_us - t;
		}
	}
	pthread_mutex_unlock(&wq->jobs_mutex);
	return dsthead;
}
