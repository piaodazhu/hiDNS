#ifndef DNS_MODULE_H
#define DNS_MODULE_H

#include "dns_utils.h"
#include "ins_cache.h"

void 
dns_module (int clientfd, char* pktbuf, int buflen, const struct prefix_path *path);

#endif