#ifndef IDNS_AOF_H
#define IDNS_AOF_H
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <bits/stdint-uintn.h>
#include <pthread.h>
#include "command.h"
#include "idns_pt.h"

typedef struct AOF_record {
    uint16_t length;
    char* buffer;
    uint16_t checksum;
} AOF_record_t;

uint16_t crc16(const char *buf, uint16_t len);

int idns_aof_init(const char* filename, int len);

int idns_aof_load(prefix_tree_node_t* pt);

int idns_aof_append(const char* buf, uint16_t len);

int idns_aof_rewrite(prefix_tree_node_t* pt);


#endif