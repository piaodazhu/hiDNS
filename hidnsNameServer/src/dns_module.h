#ifndef DNS_MODULE_H
#define DNS_MODULE_H

#include "dns_utils.h"
#include "peccache.h"
#include "hidns_events.h"

void 
dns_module (void *sargs, char* pktbuf, int buflen, const struct prefix_path *path);

#endif