#ifndef INS_REMOTE_MODULE_H
#define INS_REMOTE_MODULE_H
#include "loadconf.h"
#include "ins_cache.h"
#include "hidns_events.h"

void ins_remote_module(void *sargs, char* pktbuf, int pktlen, const struct prefix_path *path);

#endif