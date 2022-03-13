#include "idns_aof.h"

pthread_mutex_t aof_mxlock;
pthread_rwlock_t is_being_rewritten;
pthread_mutex_t buf_mxlock;
char *aof_filename;
char tmpbuf[4 * 4096];
int tmpbuf_len;

static const uint16_t crc16tab[256]= {
    0x0000,0x1021,0x2042,0x3063,0x4084,0x50a5,0x60c6,0x70e7,
    0x8108,0x9129,0xa14a,0xb16b,0xc18c,0xd1ad,0xe1ce,0xf1ef,
    0x1231,0x0210,0x3273,0x2252,0x52b5,0x4294,0x72f7,0x62d6,
    0x9339,0x8318,0xb37b,0xa35a,0xd3bd,0xc39c,0xf3ff,0xe3de,
    0x2462,0x3443,0x0420,0x1401,0x64e6,0x74c7,0x44a4,0x5485,
    0xa56a,0xb54b,0x8528,0x9509,0xe5ee,0xf5cf,0xc5ac,0xd58d,
    0x3653,0x2672,0x1611,0x0630,0x76d7,0x66f6,0x5695,0x46b4,
    0xb75b,0xa77a,0x9719,0x8738,0xf7df,0xe7fe,0xd79d,0xc7bc,
    0x48c4,0x58e5,0x6886,0x78a7,0x0840,0x1861,0x2802,0x3823,
    0xc9cc,0xd9ed,0xe98e,0xf9af,0x8948,0x9969,0xa90a,0xb92b,
    0x5af5,0x4ad4,0x7ab7,0x6a96,0x1a71,0x0a50,0x3a33,0x2a12,
    0xdbfd,0xcbdc,0xfbbf,0xeb9e,0x9b79,0x8b58,0xbb3b,0xab1a,
    0x6ca6,0x7c87,0x4ce4,0x5cc5,0x2c22,0x3c03,0x0c60,0x1c41,
    0xedae,0xfd8f,0xcdec,0xddcd,0xad2a,0xbd0b,0x8d68,0x9d49,
    0x7e97,0x6eb6,0x5ed5,0x4ef4,0x3e13,0x2e32,0x1e51,0x0e70,
    0xff9f,0xefbe,0xdfdd,0xcffc,0xbf1b,0xaf3a,0x9f59,0x8f78,
    0x9188,0x81a9,0xb1ca,0xa1eb,0xd10c,0xc12d,0xf14e,0xe16f,
    0x1080,0x00a1,0x30c2,0x20e3,0x5004,0x4025,0x7046,0x6067,
    0x83b9,0x9398,0xa3fb,0xb3da,0xc33d,0xd31c,0xe37f,0xf35e,
    0x02b1,0x1290,0x22f3,0x32d2,0x4235,0x5214,0x6277,0x7256,
    0xb5ea,0xa5cb,0x95a8,0x8589,0xf56e,0xe54f,0xd52c,0xc50d,
    0x34e2,0x24c3,0x14a0,0x0481,0x7466,0x6447,0x5424,0x4405,
    0xa7db,0xb7fa,0x8799,0x97b8,0xe75f,0xf77e,0xc71d,0xd73c,
    0x26d3,0x36f2,0x0691,0x16b0,0x6657,0x7676,0x4615,0x5634,
    0xd94c,0xc96d,0xf90e,0xe92f,0x99c8,0x89e9,0xb98a,0xa9ab,
    0x5844,0x4865,0x7806,0x6827,0x18c0,0x08e1,0x3882,0x28a3,
    0xcb7d,0xdb5c,0xeb3f,0xfb1e,0x8bf9,0x9bd8,0xabbb,0xbb9a,
    0x4a75,0x5a54,0x6a37,0x7a16,0x0af1,0x1ad0,0x2ab3,0x3a92,
    0xfd2e,0xed0f,0xdd6c,0xcd4d,0xbdaa,0xad8b,0x9de8,0x8dc9,
    0x7c26,0x6c07,0x5c64,0x4c45,0x3ca2,0x2c83,0x1ce0,0x0cc1,
    0xef1f,0xff3e,0xcf5d,0xdf7c,0xaf9b,0xbfba,0x8fd9,0x9ff8,
    0x6e17,0x7e36,0x4e55,0x5e74,0x2e93,0x3eb2,0x0ed1,0x1ef0
};
  
uint16_t crc16(const char *buf, uint16_t len) 
{
    uint16_t counter;
    uint16_t crc = 0;
    for (counter = 0; counter < len; counter++)
            crc = (crc<<8) ^ crc16tab[((crc>>8) ^ *buf++)&0x00FF];
    return crc;
}

int idns_aof_init(const char* filename, int len)
{
    pthread_mutex_init(&aof_mxlock, NULL);
    pthread_rwlock_init(&is_being_rewritten, NULL);
    pthread_mutex_init(&buf_mxlock, NULL);
    tmpbuf_len = 0;
    aof_filename = malloc(1024);
    memcpy(aof_filename, filename, len);
    aof_filename[len] = 0;
#ifdef AOF_DEBUG
        printf("AOF: append-only file initialized\n");
#endif
    return 0;
}

int idns_aof_read_cmd(FILE *fp, clientcommand_t* cmd)
{
    uint16_t len;
    uint16_t checksum;
    size_t readlen;
    char readbuf[1024];
    readlen = fread(&len, 2, 1, fp);
    if (readlen == 0)
        return 0;
    if (readlen != 1 || len >= 1024)
        return -1;
    readlen = fread(readbuf, 1, len, fp);
    if (readlen != len)
        return -2;
    readlen = fread(&checksum, 2, 1, fp);
    if (readlen != 1 || crc16(readbuf, len) != checksum)
        return -3;
    if (idns_cmddec_cmd(cmd, len, readbuf) < 0) {
        return -4;
    }
    return len;
}

int idns_aof_load(prefix_tree_node_t* pt)
{
    FILE *fp = fopen(aof_filename, "rb");
    if (fp == NULL) {
#ifdef AOF_DEBUG
        printf("AOF: no aof to be loaded.\n");
#endif
        return 0;
    }
#ifdef AOF_DEBUG
        printf("AOF: loading prefix tree from existing aof...\n");
#endif
    int ret = 0;
    int count = 0;
    do {
        clientcommand_t* cmd = idns_cmdmem_init();
        ret = idns_aof_read_cmd(fp, cmd);
        if (ret == 0) {
            break;
        } 
        else if (ret < 0) {
            printf("[x] aof load error!");
            exit(1);
        }

        if (cmd->opcode == IDNS_CMD_OPCODE_DEL) {
            ret = prefix_tree_node_delete_fast(pt, cmd);
        } else {
            ret = prefix_tree_node_insert_fast(pt, cmd);
        }
        if (ret == -2) {
            printf("[x] prefix tree rebuild error! rocde = %d\n", ret);
            exit(1);
        }

        idns_cmdmem_free(cmd);
        ++count;
    } while(1);
#ifdef AOF_DEBUG
        printf("AOF: load %d commands from AOF.\n", count);
#endif
    return count;
}

int idns_aof_append(const char* buf, uint16_t len) 
{
    uint16_t checksum;
    checksum = crc16(buf, len);
    if (pthread_rwlock_tryrdlock(&is_being_rewritten) == 0) {
#ifdef AOF_DEBUG
        printf("AOF: append command record to aof.\n");
#endif
        pthread_mutex_lock(&aof_mxlock); 
        FILE *fp = fopen(aof_filename, "ab");
        fwrite(&len, 2, 1, fp);
        fwrite(buf, 1, len, fp);
        fwrite(&checksum, 2, 1, fp);
        fclose(fp);
        pthread_mutex_unlock(&aof_mxlock);
        pthread_rwlock_unlock(&is_being_rewritten);
    } else {
#ifdef AOF_DEBUG
        printf("AOF: append command record to tmp buffer.\n");
#endif
        pthread_mutex_lock(&buf_mxlock);
        if (tmpbuf_len + len + 4 >= 4 * 4096) {
            printf("[x] buffer full!\n");
        } else {
            memcpy(tmpbuf + tmpbuf_len, &len, 2);
            tmpbuf_len += 2;
            memcpy(tmpbuf + tmpbuf_len, buf, len);
            tmpbuf_len += len;
            memcpy(tmpbuf + tmpbuf_len, &checksum, 2);
            tmpbuf_len += 2;
        }
        pthread_mutex_unlock(&buf_mxlock);
    }
    return 0;
}

void node2cmd(prefix_tree_node_t* node, clientcommand_t* cmd, char* complete_prefix, int complete_prefixlen)
{
    cmd->entity_id = node->entity_id;
    cmd->timestamp = 0;
    cmd->prefixexpiretime = node->expiretime;
    cmd->opcode = IDNS_CMD_OPCODE_ADD;
    cmd->prefixbuflen = complete_prefixlen;
    cmd->prefixbuf = malloc(complete_prefixlen);
    memcpy(cmd->prefixbuf, complete_prefix, complete_prefixlen);
    memcpy(cmd->token, node->token, 16);
    cmd->valuetype = IDNS_CMD_VALUETYPE_NON; // TBD
    cmd->valuelen = 0;
}

void aof_rewrite_callback(void* arg1, void* arg2, void* arg3, void* arg4)
{
    prefix_tree_node_t *node = (prefix_tree_node_t*)arg1;
    char *complete_prefix = (char*) arg2;
    int *complete_prefixlen = (int*) arg3;
    FILE *fp = (FILE*) arg4;

    char buf[1024];
    uint16_t len, checksum;
    
    clientcommand_t* cmd = idns_cmdmem_init();
    node2cmd(node, cmd, complete_prefix, *complete_prefixlen);
    len = idns_cmdenc_cmd(cmd, 1024, buf);
    idns_cmdmem_free(cmd);

    checksum = crc16(buf, len);
    fwrite(&len, 2, 1, fp);
    fwrite(buf, 1, len, fp);
    fwrite(&checksum, 2, 1, fp);
#ifdef AOF_DEBUG
        printf("AOF: rewrite appending prefix %.*s.\n", *complete_prefixlen, complete_prefix);
#endif
    return;
}

int idns_aof_rewrite(prefix_tree_node_t* pt)
{
#ifdef AOF_DEBUG
    printf("AOF: start rewriting aof...\n");
#endif
    pthread_rwlock_wrlock(&is_being_rewritten);
    // backup the previous file
    // travel the tree with callback
    // save to the file  
    pthread_mutex_lock(&aof_mxlock);
    FILE *fp = fopen(aof_filename, "wb");
    fclose(fp);
    fp = fopen(aof_filename, "ab");
    prefix_tree_visit_withcallback(pt, aof_rewrite_callback, fp);
    fclose(fp);
    // pthread_mutex_lock(&buf_mxlock);
    // int fd = fopen(aof_filename, "ab");
    // fwrite(tmpbuf, 1, tmpbuf_len, fd);
    // fclose(fd);
    // tmpbuf_len = 0;
    // tmpbuf_ptr = 0;
    // pthread_mutex_unlock(&buf_mxlock);
    pthread_mutex_unlock(&aof_mxlock);
    pthread_rwlock_unlock(&is_being_rewritten);

    // check buffer [again] to make sure buffer clean.
    pthread_mutex_lock(&aof_mxlock);
    pthread_mutex_lock(&buf_mxlock);
    if (tmpbuf_len != 0) {
        FILE *fp = fopen(aof_filename, "ab");
        fwrite(tmpbuf, 1, tmpbuf_len, fp);
        fclose(fp);
        tmpbuf_len = 0;
    }
    pthread_mutex_unlock(&buf_mxlock);
    pthread_mutex_unlock(&aof_mxlock);
 #ifdef AOF_DEBUG
        printf("AOF: aof rewrite done!\n");
#endif   
    return 0;
}
