#ifndef DNS_MODULE_H
#define DNS_MODULE_H

#include "dns_utils.h"

void 
dns_module (int clientfd, char* pktbuf, int buflen, const struct prefix_path *path);

#endif