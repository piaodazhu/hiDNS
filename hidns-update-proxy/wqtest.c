#include "workqueue.h"
#include <unistd.h>

// #define MULTITHREAD

rr_update_cmd_t* gen_testcmd(int tag)
{
	int plen;
	char *pfx = malloc(16);
	plen = snprintf(pfx, 256, "/testprefix/%d/", tag);
	hidns_update_command* c = updatemsg_new_command();
	c->opcode = COMMAND_OPCODE_ADDRR;
	c->rrttl = 86400;
	c->rrtype  = COMMAND_RRTYPE_A;
	c->rrprefixbuf = pfx;
	c->rrprefixlen = plen;
	c->rrvaluebuf = "1.1.1.1";
	c->rrvaluelen = strlen("1.1.1.1");
	rr_update_cmd_t* cmd = updatecmd_new();
	if ((updatecmd_init(cmd, c, NULL))!=0) {
		return NULL;
	}
	cmd->retrycnt = tag;
	return cmd;
}

rr_update_job_t* gen_testjob(int tag)
{
	rr_update_job_t *job = updatejob_new();
	job->pid = tag;
	return job;
}

void print_wq(workqueue_t *wq, const char *title)
{
	pthread_mutex_lock(&wq->jobs_mutex);
	printf("queue [%s] (%u): \n", title, wq->statistics);
	rr_update_job_t *jobptr = wq->jobs_list;
	while (jobptr != NULL)
	{
		printf("job %d, cmdbatch size = %d, cmds: ", jobptr->pid, jobptr->cmdbatchsize);
		rr_update_cmd_t *cmd = jobptr->cmdbatch;
		while (cmd) {
			printf("%u ", cmd->retrycnt);
			// printf("%.*s", cmd->nsupdatebuflen, cmd->nsupdatebuf);
			cmd = cmd->next;
		}
		printf("\nnsupdate:\n");
		char updatebuf[1024];
		int len = updatecmdlist_mkbuf(jobptr->cmdbatch, updatebuf, 1024);
		printf("%.*s", len, updatebuf);
		printf("\n");
		jobptr = jobptr->next;
	}
	pthread_mutex_unlock(&wq->jobs_mutex);
}
struct workerarg {
	workqueue_t *from;
	workqueue_t *to;
};

void* worker_thread(void *arg)
{
	struct workerarg *wa = arg;
	workqueue_t *from = wa->from;
	workqueue_t *to = wa->to;

	int cnt = 1;
	rr_update_job_t *job = NULL;
	rr_update_job_t *joblist = NULL;
	while (1) {
		if (cnt % 5 == 0) {
			joblist = workqueue_get_joblist(from, 180);
			rr_update_job_t *jobptr;
			jobptr = joblist;
			while (jobptr != NULL) {
				job = jobptr;
				jobptr = jobptr->next;
				workqueue_add_job(from, job);
			}
		}
		else {
			job = workqueue_get_job(from);
			workqueue_add_job(to, job);
		}
		++cnt;
	}
	return NULL;
}

void* watcher_thread(void *arg)
{
	struct workerarg *wa = arg;
	workqueue_t *wq = wa->from;
	workqueue_t *eq = wa->to;
	
	int cnt;
	while (1)
	{
		printf("\n--- %dst watching ---\n", cnt);
		print_wq(wq, "WaitQueue");
		print_wq(eq, "ExecQueue");
		sleep(1);
		cnt++;
	}
	return NULL;
}

workqueue_t WaitQueue, ExecQueue;

int main()
{
	printf("===initialize===\n");
	int i;
	rr_update_cmd_t* cmds[16];
	rr_update_job_t* jobs[16];
	workqueue_init(&WaitQueue);
	workqueue_init(&ExecQueue);
	for (i = 0; i < 16; i++) {
		cmds[i] = gen_testcmd(i);
		jobs[i] = gen_testjob(i);
		updatejob_add_cmd(jobs[i], cmds[i]);
		workqueue_add_job(&WaitQueue, jobs[i]);
	}
	print_wq(&WaitQueue, "WaitQueue");
	print_wq(&ExecQueue, "ExecQueue");

	printf("===queue trans===\n");
	rr_update_job_t *job;
	for (i = 0; i < 8; i++) {
		job = workqueue_get_job(&WaitQueue);
		// printf("get job %d\n", job->pid);
		workqueue_add_job(&ExecQueue, job);
	}
	print_wq(&WaitQueue, "WaitQueue");
	print_wq(&ExecQueue, "ExecQueue");

#ifndef MULTITHREAD
	printf("===jobs merge===\n");
	rr_update_job_t *joblist;
	joblist = workqueue_get_joblist(&WaitQueue, 256);
	job = updatejob_merge_jobs(joblist);
	workqueue_add_job(&ExecQueue, job);
	print_wq(&WaitQueue, "WaitQueue");
	print_wq(&ExecQueue, "ExecQueue");

	printf("===job free===\n");
	for (i = 0; i < 8; i++) {
		job = workqueue_get_job(&ExecQueue);
		updatejob_free(job);
	}
	print_wq(&WaitQueue, "WaitQueue");
	print_wq(&ExecQueue, "ExecQueue");
	
	printf("===job split===\n");
	job = workqueue_get_job(&ExecQueue);
	joblist = updatejob_split_job(job, 0);
	rr_update_job_t *jobptr;
	jobptr = joblist;
	while (jobptr != NULL) {
		job = jobptr;
		jobptr = jobptr->next;
		workqueue_add_job(&WaitQueue, job);
	}
	print_wq(&WaitQueue, "WaitQueue");
	print_wq(&ExecQueue, "ExecQueue");
#else
	printf("===multi thread===\n");
	WaitQueue.statistics = 0;
	ExecQueue.statistics = 0;
	pthread_t worker1, worker2, worker3, worker4, watcher;
	struct workerarg arg1, arg2;
	arg1.from = &WaitQueue;
	arg1.to = &ExecQueue;
	arg2.from = &ExecQueue;
	arg2.to = &WaitQueue;
	pthread_create(&worker1, NULL, worker_thread, &arg1);
	pthread_create(&worker2, NULL, worker_thread, &arg2);
	pthread_create(&worker3, NULL, worker_thread, &arg1);
	pthread_create(&worker4, NULL, worker_thread, &arg2);
	pthread_create(&watcher, NULL, watcher_thread, &arg1);
	while (1) {
		sleep(10);
	}
#endif
	return 0;
}