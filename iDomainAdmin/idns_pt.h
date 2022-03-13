#ifndef IDNS_PT_H
#define IDNS_PT_H

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include "security.h"
#include "command.h"
#include "globalconfig.h"

// TBD:
// each tree node should maintain one public key of this prefix
// entity_id is just for validating the command, so get rid of it and throw it to EIT
// each tree node should maintain a set of value: A, CNAME, TXT...
// for bad Proxy, it may use clients' registerinfo doing bad thing. Suppose Proxy with certificate is good.
// what if Proxy still do bad thing? Some report from clients will send the entity to blacklist.
typedef struct prefix_tree_node {
        int componentlen;
        char* icn_component;
        int expiretime;

        u_int64_t entity_id;
        char token[16];

        int children_num;
        struct prefix_tree_node *children[MAX_PTNODE_CHILDREN_NUM];
        struct prefix_tree_node *parent; // only in aof
}prefix_tree_node_t;

prefix_tree_node_t* 
prefix_tree_init();
 
prefix_tree_node_t* 
prefix_tree_node_alloc(unsigned int componentlen, char* component);

int 
prefix_tree_node_free(prefix_tree_node_t* entry);

// out-of-date
prefix_tree_node_t* 
prefix_tree_findbyprefix(prefix_tree_node_t* root, 
                        unsigned int prefixbuflen, char* prefixbuf);

int 
prefix_tree_checkprefix(prefix_tree_node_t* root, 
                        clientcommand_t* cmd);

int
prefix_tree_node_insert(prefix_tree_node_t* root, 
                        clientcommand_t* cmd);

int
prefix_tree_node_delete(prefix_tree_node_t* root,
                        clientcommand_t* cmd);

// these two only for aof load
int
prefix_tree_node_insert_fast(prefix_tree_node_t* root, 
                        clientcommand_t* cmd);

int
prefix_tree_node_delete_fast(prefix_tree_node_t* root,
                        clientcommand_t* cmd);

int
prefix_tree_node_delete_withcallback(prefix_tree_node_t* root,
                        clientcommand_t* cmd, void (*callback)(void*, void*),
                        void* arg1, void* arg2);

int 
prefix_tree_destroy(prefix_tree_node_t* root);

void 
prefix_tree_print(prefix_tree_node_t* root);

void 
prefix_tree_visit_withcallback(prefix_tree_node_t* root, 
                        void (*callback)(void*, void*, void*, void*), 
                        void* arg);

static void
swap(prefix_tree_node_t** x, prefix_tree_node_t** y) {
     prefix_tree_node_t* t = *x;
     *x = *y;
     *y = t;
}

typedef struct ptnode_item {
        struct prefix_tree_node *node;
        unsigned int child_idx;
}ptnode_item_t;

typedef struct ptnode_stack {
        int top;
        struct ptnode_item item[MAX_PTNODE_DEPTH];
}ptnode_stack_t;

ptnode_stack_t*
ptnode_stack_init();

int
ptnode_stack_push(ptnode_stack_t* st, prefix_tree_node_t* node, unsigned int child_idx);

ptnode_item_t*
ptnode_stack_pop(ptnode_stack_t* st);

ptnode_item_t*
ptnode_stack_top(ptnode_stack_t* st);

// queue
typedef struct ptnode_queue {
        int front, rear;
        struct prefix_tree_node* item[MAX_PTNODE_WIDTH];
}ptnode_queue_t;

ptnode_queue_t*
ptnode_queue_init();

int
ptnode_queue_push(ptnode_queue_t* qu, prefix_tree_node_t* node);

prefix_tree_node_t*
ptnode_queue_pop(ptnode_queue_t* qu);

prefix_tree_node_t*
ptnode_queue_front(ptnode_queue_t* qu);

static int
ptnode_queue_empty(ptnode_queue_t* qu)
{
        return qu->front == qu->rear;
}

#endif