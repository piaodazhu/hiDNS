#ifndef INS_REMOTE_MODULE_H
#define INS_REMOTE_MODULE_H
#include "loadconf.h"
#include "ins_cache.h"

void ins_remote_module(int clientfd, char* pktbuf, int pktlen, const struct prefix_path *path);

#endif