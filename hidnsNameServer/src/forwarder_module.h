#ifndef FORWARDER_MODULE_H
#define FORWARDER_MODULE_H
#include "loadconf.h"
#include "peccache.h"
#include "hidns_events.h"

void ins_remote_module(void *sargs, char* pktbuf, int pktlen, const struct prefix_path *path);

#endif