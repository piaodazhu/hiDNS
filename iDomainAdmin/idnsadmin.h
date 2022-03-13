#ifndef IDNS_ADMIN_H
#define IDNS_ADMIN_H

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include "command.h"
#include "security.h"
#include "idns_eit.h"
#include "idns_pt.h"
#include "ipsock.h"
#include "updatezone.h"
#include "globalconfig.h"
#include "idns_aof.h"
void
idns_rrup_callback(void* arg1, void* arg2);

#endif