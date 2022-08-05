#ifndef SERVER_DEMO_H
#define SERVER_DEMO_H

#include "eventcontext.h"
#include "updatemsgtools.h"
#include "verifystruct.h"
#include "workqueue.h"
#include "ins_verifyasync.h"

#define SERVER_PORT		1038
#define SERVER_IP		"127.0.0.1"
#define MAX_EPOLLSIZE		1000
#define MAX_BUFSIZE		4096
#define TIME_SUB_MS(tv1, tv2)  ((tv1.tv_sec - tv2.tv_sec) * 1000 + (tv1.tv_usec - tv2.tv_usec) / 1000)


#endif