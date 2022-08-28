#ifndef IDNS_EIT_H
#define IDNS_EIT_H
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include "security.h"
#include "globalconfig.h"

typedef struct entity_info_entry {
        u_int64_t entity_id;
        u_int64_t auth_entity_id;
        int pkeylen;
        char* pkey;
        int pkeyexpiretime;
        int someothers;

        struct entity_info_entry* pre;
        struct entity_info_entry* next;
}entity_info_entry_t;


entity_info_entry_t* 
entity_info_table_init();

entity_info_entry_t* 
entity_info_entry_alloc(clientcertificate_t* cert);

int 
entity_info_entry_free(entity_info_entry_t* entry);

entity_info_entry_t* 
entity_info_table_findbyID(entity_info_entry_t* head, 
                        u_int64_t entity_ID);

int
entity_info_entry_insert(entity_info_entry_t* head, 
                        clientcertificate_t* cert);

int
entity_info_entry_delete(entity_info_entry_t* head, 
                        clientcertificate_t* cert);

int 
entity_info_table_destroy(entity_info_entry_t* head);

void 
entity_info_table_print(entity_info_entry_t* head);

#endif