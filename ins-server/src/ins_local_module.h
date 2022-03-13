#ifndef INS_LOCAL_MODULE_H
#define INS_LOCAL_MODULE_H

#include "loadconf.h"
#include "dns_utils.h"

void ins_local_module(int clientfd, char* pktbuf, int pktlen, const struct prefix_path *path);


#endif