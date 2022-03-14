#ifndef IDNS_COMMAND_H
#define IDNS_COMMAND_H

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
//#include <unistd.h>
#include <time.h>
#include <string.h>
#include <netinet/in.h>



#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))

#define IDNS_RCODE_SUCCEED_ADD          0x00
#define IDNS_RCODE_SUCCEED_UPDATE       0x01
#define IDNS_RCODE_SUCCEED_DEL          0x08
#define IDNS_RCODE_ALREADY_DEL          0x09

#define IDNS_RCODE_INVALID_PACKET       0x10
#define IDNS_RCODE_INVALID_PREFIX       0x11
#define IDNS_RCODE_INVALID_TIMESTAMP    0x12
#define IDNS_RCODE_INVALID_OPCODE       0x13
#define IDNS_RCODE_INVALID_VALUETYPE    0x14

#define IDNS_RCODE_UNAUTH_PACKET        0x18
#define IDNS_RCODE_UNAUTH_OP            0x19

#define IDNS_CMD_VALUETYPE_NON      0
#define IDNS_CMD_VALUETYPE_A        1
#define IDNS_CMD_VALUETYPE_TXT      2
#define IDNS_CMD_VALUETYPE_CNAME    3

#define IDNS_CMD_OPCODE_NON 0
#define IDNS_CMD_OPCODE_ADD 1
#define IDNS_CMD_OPCODE_DEL 2

typedef struct clientcommand {
        u_int64_t entity_id;
        u_int32_t timestamp;
        u_int32_t prefixexpiretime;
        u_int16_t opcode;
        u_int16_t prefixbuflen;
        char* prefixbuf;
        
        char token[16];

        u_int16_t valuetype;
        u_int16_t valuelen;
        char* valuebuf;
}clientcommand_t;

clientcommand_t*
idns_cmdmem_init();

void
idns_cmdmem_free(clientcommand_t *cmd);

int
idns_cmddec_buf2(char *buf, char **dst, u_int16_t len);

int
idns_cmddec_cmd(clientcommand_t *cmd, unsigned int rcvlen, char *rcvbuf);

int
idns_cmdenc_cmd(clientcommand_t *cmd, unsigned int bound, char *sendbuf);


static int
idns_cmddec_1byte(char *buf, u_int8_t *dst)
{
	*dst = *buf;
	return 1;
}

static int
idns_cmddec_2byte(char *buf, u_int16_t *dst)
{
	u_int16_t *px = (u_int16_t*)buf;
	u_int16_t x = *px;
	*dst = ntohs(x);
	return 2;
}

static int
idns_cmddec_4byte(char *buf, u_int32_t *dst)
{
	u_int32_t *px = (u_int32_t*)buf;
	u_int32_t x = *px;
	*dst = ntohl(x);
	return 4;
}

static int
idns_cmddec_8byte(char *buf, u_int64_t *dst)
{
	u_int64_t *px = (u_int64_t*)buf;
	u_int64_t x = *px;
	*dst = ntohll(x);
	return 8;
}

static int
idns_cmddec_buf(char *buf, char *dst, u_int16_t len)
{
	memcpy(dst, buf, len);
	return len;
}

///// 

static char*
idns_cmddenc_1byte(char *buf, u_int8_t n)
{
	*buf++ = n;
	return buf;
}

static char*
idns_cmdenc_2byte(char *buf, u_int16_t n)
{
    n = htons(n);
    *buf++ = (n & 0xFF);
    *buf++ = ((n >> 8) & 0xFF);
    return buf;
}

static char*
idns_cmdenc_4byte(char *buf, u_int32_t n)
{
    n = htonl(n);
    *buf++ = (n & 0xFF);
    *buf++ = ((n >> 8) & 0xFF);
    *buf++ = ((n >> 16) & 0xFF);
    *buf++ = ((n >> 24) & 0xFF);
    return buf;
}

static char*
idns_cmdenc_8byte(char *buf, u_int64_t n)
{
	n = htonll(n);
    *buf++ = (n & 0xFF);
    *buf++ = ((n >> 8) & 0xFF);
    *buf++ = ((n >> 16) & 0xFF);
    *buf++ = ((n >> 24) & 0xFF);
    *buf++ = ((n >> 32) & 0xFF);
    *buf++ = ((n >> 40) & 0xFF);
    *buf++ = ((n >> 48) & 0xFF);
    *buf++ = ((n >> 56) & 0xFF);
    return buf;
}

static char*
idns_cmdenc_buf(char *buf, char *src, u_int16_t len)
{
	memcpy(buf, src, len);
	return buf + len;
}

#endif