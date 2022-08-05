#ifndef WORK_QUEUE_H
#define WORK_QUEUE_H

#include "eventcontext.h"
#include "updatemsgfmt.h"


#define LL_ADD(item, list) { \
	if (list != NULL) list->prev = item; \
	item->prev = NULL; \
	item->next = list; \
	list = item; \
}

#define LL_REMOVE(item, list) { \
	if (item->prev != NULL) item->prev->next = item->next; \
	if (item->next != NULL) item->next->prev = item->prev; \
	if (list == item) list = item->next; \
	item->prev = item->next = NULL; \
}

#define TIME_SUB_US(tv1, tv2)  ((tv1.tv_sec - tv2.tv_sec) * 1000000 + (tv1.tv_usec - tv2.tv_usec))

#define TIME_ADD_US(tv_in, us_in, tv_out)  { \
	tv_out.tv_sec = tv_in.tv_sec + (tv_in.tv_usec + us_in) / 1000000; \
	tv_out.tv_usec = (tv_in.tv_usec + us_in) % 1000000; \
}

// a single update command and the nsupdate command buffer
typedef struct rr_update_cmd {
	unsigned char cmdstate;
	unsigned char retrycnt;
	unsigned short nsupdatebuflen;
	unsigned char *nsupdatebuf;
	hidns_update_command *cmd;
	session_ctx_t *cmdctx;
	
	struct rr_update_cmd *prev;
	struct rr_update_cmd *next;
} rr_update_cmd_t;

// a single zoneupdate job may contain multiple nsupdate command
typedef struct rr_update_job {
	int state;
	int pid;
	int cmdbatchsize;
	rr_update_cmd_t *cmdbatch;

	struct rr_update_job *prev;	
	struct rr_update_job *next;
} rr_update_job_t;

// a single workqueue may contain multiple zoneupdate job
typedef struct workqueue {
	rr_update_job_t *jobs_list;
	unsigned int statistics;
	pthread_mutex_t jobs_mutex;
	pthread_cond_t jobs_cond;
} workqueue_t;

// workqueue
// init shutdown addjob getjob
workqueue_t* workqueue_new();
void workqueue_free(workqueue_t *wq);
void workqueue_init(workqueue_t* wq);
void workqueue_clear(workqueue_t *wq);
int workqueue_add_job(workqueue_t *wq, rr_update_job_t *job);
rr_update_job_t* workqueue_get_job(workqueue_t *wq);
rr_update_job_t* workqueue_get_joblist(workqueue_t *wq, int totalcmdbuflen);
rr_update_job_t* workqueue_get_njobs(workqueue_t *wq, int maxjobcnt, int timeout_us, int *remainjobcnt, int *remaintime_us);

// updatejob
// new free addcmd merge split
rr_update_job_t* updatejob_new();
void updatejob_free(rr_update_job_t *job);
void updatejob_init(rr_update_job_t* job);
void updatejob_clear(rr_update_job_t *job);
int updatejob_add_cmd(rr_update_job_t *job, rr_update_cmd_t *cmd);
rr_update_job_t* updatejob_merge_jobs(rr_update_job_t *joblist);
rr_update_job_t* updatejob_split_job(rr_update_job_t *job_in, int factor);

// updatecmd
// new free mkcmd
rr_update_cmd_t* updatecmd_new();
void updatecmd_free(rr_update_cmd_t *cmd);
int updatecmd_init(rr_update_cmd_t *cmd, hidns_update_command *c, session_ctx_t *cmdctx);
int updatecmdlist_mkbuf(const rr_update_cmd_t *cmd, unsigned char* buf, int buflen);

#endif