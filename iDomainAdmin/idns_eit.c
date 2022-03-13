#include "idns_eit.h"
pthread_rwlock_t eit_rwlock;

entity_info_entry_t* 
entity_info_table_init()
{
        entity_info_entry_t* head = (entity_info_entry_t*) malloc (sizeof(entity_info_entry_t));
        head->pre = NULL;
        head->next = NULL;
        head->entity_id = 0;
        pthread_rwlock_init(&eit_rwlock, NULL);

#ifdef EIT_DEBUG
        printf("EIT: a table initialized\n");
#endif
        return head;
}

entity_info_entry_t* 
entity_info_entry_alloc(clientcertificate_t* cert)
{
        entity_info_entry_t* entry = (entity_info_entry_t*) malloc (sizeof(entity_info_entry_t));
        entry->entity_id = cert->entity_id;
        entry->pkeyexpiretime = cert->cert_expiretime;
        entry->pkeylen = cert->keybuflen;
        entry->pkey = malloc(cert->keybuflen);
        memcpy(entry->pkey, cert->keybuf, cert->keybuflen);
        entry->next = NULL;
        entry->pre = NULL;
        return entry;
}

int 
entity_info_entry_free(entity_info_entry_t* entry)
{
        free(entry->pkey);
        free(entry);
        return 0;
}

entity_info_entry_t* 
entity_info_table_findbyID(entity_info_entry_t* head, 
                        u_int64_t entity_ID)
{
        pthread_rwlock_rdlock(&eit_rwlock);
        entity_info_entry_t* p = head->next;
        while (p != NULL)
        {
                if (p->entity_id == entity_ID) {
                        pthread_rwlock_unlock(&eit_rwlock);
                        #ifdef EIT_DEBUG
                                printf("EIT: ID found: %ld\n", entity_ID);
                        #endif
                        return p;
                }
                p = p->next;
        }
        
        pthread_rwlock_unlock(&eit_rwlock);

#ifdef EIT_DEBUG
        printf("EIT: ID not found: %ld\n", entity_ID);
#endif
        return p;
}

int
entity_info_entry_insert(entity_info_entry_t* head, 
                        clientcertificate_t* cert)
{
        pthread_rwlock_wrlock(&eit_rwlock);
        entity_info_entry_t* p = head->next;
        while (p != NULL)
        {
                if (p->entity_id == cert->entity_id) {
                        p->pkeylen = cert->keybuflen;
                        free(p->pkey);
                        p->pkey = malloc(cert->keybuflen);
                        memcpy(p->pkey, cert->keybuf, cert->keybuflen);
                        p->pkeyexpiretime = cert->cert_expiretime;
                        
                        #ifdef EIT_DEBUG
                                printf("EIT insert: ID found: %ld. just edit\n", cert->entity_id);
                        #endif
                        pthread_rwlock_unlock(&eit_rwlock);
                        return -1;
                }
                p = p->next;
        }

        entity_info_entry_t* entry = head->next;
        if (head->next == NULL) {
                head->next = entry;
                entry->pre = head;
                entry->next = NULL;
        } else {
                entity_info_entry_t* p = head->next;
                head->next = entry;
                entry->pre = head;
                p->pre = entry;
                entry->next = p;
        }
        
#ifdef EIT_DEBUG
        printf("EIT insert: GID=%ld, key=%.*s. succeed\n", entry->entity_id, entry->pkeylen, entry->pkey);
#endif
        pthread_rwlock_unlock(&eit_rwlock);
        return 0;
}

int
entity_info_entry_delete(entity_info_entry_t* head,
                        clientcertificate_t* cert)
{
        pthread_rwlock_wrlock(&eit_rwlock);
        entity_info_entry_t* p = head->next;
        while (p != NULL)
        {
                if (p->entity_id == cert->entity_id) {
                        // delete
                        entity_info_entry_t*  pre = p->pre;
                        entity_info_entry_t*  next = p->next;
                        if (next == NULL) {
                                pre->next = NULL;
                        } else {
                                pre->next = next;
                                next->pre = pre;
                        }
                        entity_info_entry_free(p);
                        
                        #ifdef EIT_DEBUG
                                printf("EIT delete: ID found: %ld. succeed\n", cert->entity_id);
                        #endif
                        pthread_rwlock_unlock(&eit_rwlock);
                        return 0;
                }
                p = p->next;
        }

        
#ifdef EIT_DEBUG
        printf("EIT delete: GID=%ld. not found\n", cert->entity_id);
#endif
        pthread_rwlock_unlock(&eit_rwlock);
        return -1;
}

int 
entity_info_table_destroy(entity_info_entry_t* head)
{
        if (head->next != NULL) return -1;
        pthread_rwlock_destroy(&eit_rwlock);
        free(head);
        return 0;
}

void 
entity_info_table_print(entity_info_entry_t* head)
{
#ifdef EIT_DEBUG
        pthread_rwlock_rdlock(&eit_rwlock);\
        printf("******EIT******\n");
        entity_info_entry_t* p = head->next;
        while (p != NULL)
        {
                printf("%ld, %.*s\n", p->entity_id, p->pkeylen, p->pkey);
                p = p->next;
        }
        printf("******END******\n");
        pthread_rwlock_unlock(&eit_rwlock);
#endif
        return;
}