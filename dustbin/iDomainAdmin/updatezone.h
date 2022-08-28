#ifndef IDNS_UPDATE_ZONE_H
#define IDNS_UPDATE_ZONE_H

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <pthread.h>
#include "iDomainAdminConfig.h"

#define IDNS_OPCODE_NON 0
#define IDNS_OPCODE_ADD 1
#define IDNS_OPCODE_DEL 2
#define IDNS_OPCODE_EDIT 3

#define IDNS_RRCLASS_NON 0
#define IDNS_RRCLASS_A 1
#define IDNS_RRCLASS_TXT 2
#define IDNS_RRCLASS_CNAME 3
// TBD: define time respond code

typedef struct idns_updateinfo {
        int opcode;
        int serverlen;
        char* server;
        int RRdomainnamelen;
        char* RRdomainname;
        int RRttl;
        int RRclass;
        int RRvaluelen;
        char* RRvalue;
}idns_updateinfo_t;

void idns_rrup_lock_init();

void idns_rrup_lock_destroy();

idns_updateinfo_t* idns_rrup_updateinfo_alloc();

void idns_rrup_updateinfo_free(idns_updateinfo_t* uinfo);

int idns_rrup_update_rr(idns_updateinfo_t* uinfo);

int idns_rrup_flush();

static inline
void idns_rrup_updateinfo_set_opcode_add(idns_updateinfo_t *uinfo) 
{
        uinfo->opcode = IDNS_OPCODE_ADD;
}

static inline
void idns_rrup_updateinfo_set_opcode_del(idns_updateinfo_t *uinfo) 
{
        uinfo->opcode = IDNS_OPCODE_DEL;
}

static inline
void idns_rrup_updateinfo_set_opcode_edit(idns_updateinfo_t *uinfo) 
{
        uinfo->opcode = IDNS_OPCODE_EDIT;
}

static inline
void idns_rrup_updateinfo_set_ttl(idns_updateinfo_t *uinfo, int ttl) 
{
        uinfo->RRttl = ttl;
}

static inline
void idns_rrup_updateinfo_set_class(idns_updateinfo_t *uinfo, int class) 
{
        uinfo->RRclass = class;
}

static inline
void idns_rrup_updateinfo_set_class_A(idns_updateinfo_t *uinfo) 
{
        uinfo->RRclass = IDNS_RRCLASS_A;
}

static inline
void idns_rrup_updateinfo_set_class_TXT(idns_updateinfo_t *uinfo)
{
        uinfo->RRclass = IDNS_RRCLASS_TXT;
}

static inline
void idns_rrup_updateinfo_set_class_CNAME(idns_updateinfo_t *uinfo)
{
        uinfo->RRclass = IDNS_RRCLASS_CNAME;
}

static inline
void idns_rrup_updateinfo_set_value(idns_updateinfo_t *uinfo, 
        const char* valuestring, unsigned int len)
{
        if (len == 0) return;
        // len must less than 256!
        uinfo->RRvaluelen = len;
        memcpy(uinfo->RRvalue, valuestring, len);
}

void idns_rrup_updateinfo_set_domainname(idns_updateinfo_t *uinfo, 
        const char* prefix, unsigned int len);

#endif