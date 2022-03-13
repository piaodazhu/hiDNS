#ifndef INSS_LOAD_CONF_H
#define INSS_LOAD_CONF_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <syslog.h>
#include "rkt.h"
#include "ins_msgformat.h"
#include "ins_prefix.h"

/* global variables */
char GLOBAL_NICKNAME[256];
char GLOBAL_DOMAINNAME[256];
struct sockaddr_in GLOBAL_LOCALADDR;
char GLOBAL_AUTHORIZER[256];

void ins_local_module(int clientfd, char* pktbuf, int pktlen, const struct prefix_path *path);
void ins_remote_module(int clientfd, char* pktbuf, int pkten, const struct prefix_path *path);
void dns_module(int clientfd, char* pktbuf, int pktlen, const struct prefix_path *path);

int load_conf_json(char *filename);

#endif