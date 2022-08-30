#ifndef INS_LOCAL_MODULE_H
#define INS_LOCAL_MODULE_H

#include "loadconf.h"
#include "dns_utils.h"
#include "peccache.h"
#include "hidns_events.h"

void ins_local_module(void *sargs, char* pktbuf, int pktlen, const struct prefix_path *path);


#endif