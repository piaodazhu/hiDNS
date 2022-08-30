#ifndef ROBIN_KARP_TABLE_H
#define ROBIN_KARP_TABLE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ipsock.h"

typedef struct prefix_path {
    int pathlen;
    char* pathbuf;
    struct sockaddr_in dst;
    void (*process_module) (void *sargs, char* pktbuf, int pktlen, const struct prefix_path *path);

    int rkv; // robin karp value
    int isfinal; // help fast finish matching
    struct prefix_path *next;
}prefix_path_t;


typedef struct robinkarp_table_item {
    int compute_mod;
    int path_num;
    struct prefix_path *path;
}robinkarp_table_item_t;


#define ROBIN_KARP_TABLE_SIZE   64
typedef struct robinkarp_table {
    int compute_mul;
    int default_mod;
    int table_len;
    struct robinkarp_table_item table[ROBIN_KARP_TABLE_SIZE];
}robinkarp_table_t;


void rkt_init();

int rkt_add_path(const char* prefix, int prefixlen, 
	void* sockbuf, int socklen, void (*process_module) (void *sargs, char* pktbuf, int pktlen, const struct prefix_path *path));

int rkt_finish_build();

int rkt_route(void *sargs, char* name, int nlen, char* pktbuf, int pktlen);

#endif