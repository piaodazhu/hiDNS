#ifndef IDNS_ADMIN_CONFIG_H
#define IDNS_ADMIN_CONFIG_H

#define IDNS_TIMESTAMP_THRESHOLD 600
// To be implemented
#define IDNS_TRUST_ANCHOR "88888888"
#define IDNS_ROOT_TOKEN 31
#define IDNS_ROOT_ENTITY_ID 101

// DNS
#define RESPONSIBLE_ZONE "bit.edu"

// network
#define RESPONSIBLE_SERVER "192.168.66.68"
#define LOCAL_PORT 1038
#define LOCAL_IP "0.0.0.0"

// global database
#define PREFIX_TREE_ROOT "/edu/bit/"
#define MAX_PTNODE_CHILDREN_NUM  256
#define MAX_PTNODE_DEPTH  10
#define MAX_PTNODE_WIDTH  1024
#define PT_DEBUG
#define AOF_DEBUG
#define EIT_DEBUG
#define PRINT_ZONE
//#define KEEP_NSU

#endif
