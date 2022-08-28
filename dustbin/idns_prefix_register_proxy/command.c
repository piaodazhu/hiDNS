#include "command.h"

clientcommand_t*
idns_cmdmem_init()
{
	clientcommand_t *cmd = (clientcommand_t*)malloc(sizeof(clientcommand_t));
	cmd->entity_id = 0;
	cmd->prefixbuflen = 0;
	cmd->valuelen = 0;
	return cmd;
}

void
idns_cmdmem_free(clientcommand_t *cmd)
{
	if (cmd->prefixbuflen != 0) {
		free(cmd->prefixbuf);
	}
	if (cmd->valuelen != 0) {
		free(cmd->valuebuf);
	}
	free(cmd);
}

int idns_cmddec_buf2(char *buf, char **dst, u_int16_t len)
{
	*dst = (char*)malloc(len);
	memcpy(*dst, buf, len);
	return len;
}

int idns_cmddec_cmd(clientcommand_t *cmd, unsigned int rcvlen, char *rcvbuf)
{
	cmd->prefixbuflen = 0;
	cmd->valuelen = 0;
	int ptr = 0;
	ptr += idns_cmddec_8byte(rcvbuf + ptr, &cmd->entity_id);
	ptr += idns_cmddec_4byte(rcvbuf + ptr, &cmd->timestamp);
	ptr += idns_cmddec_4byte(rcvbuf + ptr, &cmd->prefixexpiretime);
	ptr += idns_cmddec_2byte(rcvbuf + ptr, &cmd->opcode);
	ptr += idns_cmddec_2byte(rcvbuf + ptr, &cmd->prefixbuflen);
	if (ptr + cmd->prefixbuflen + 20 > rcvlen) {
		return -1;
	}
	ptr += idns_cmddec_buf2(rcvbuf + ptr, &cmd->prefixbuf, cmd->prefixbuflen);
	
	ptr += idns_cmddec_buf(rcvbuf + ptr, cmd->token, 16);
	ptr += idns_cmddec_2byte(rcvbuf + ptr, &cmd->valuetype);
	ptr += idns_cmddec_2byte(rcvbuf + ptr, &cmd->valuelen);
	if (ptr + cmd->valuelen > rcvlen) {
		return -1;
	}
	ptr += idns_cmddec_buf2(rcvbuf + ptr, &cmd->valuebuf, cmd->valuelen);
	return ptr;
}

int
idns_cmdenc_cmd(clientcommand_t *cmd, unsigned int bound, char *sendbuf)
{
    unsigned int total = 40 + 
                        cmd->prefixbuflen + cmd->valuelen + 
                        0;
    if (bound < total) return -1;
    char *ptr = sendbuf;
    ptr = idns_cmdenc_8byte(ptr, cmd->entity_id);
    ptr = idns_cmdenc_4byte(ptr, cmd->timestamp);
    ptr = idns_cmdenc_4byte(ptr, cmd->prefixexpiretime);
    ptr = idns_cmdenc_2byte(ptr, cmd->opcode);
    ptr = idns_cmdenc_2byte(ptr, cmd->prefixbuflen);
    ptr = idns_cmdenc_buf(ptr, cmd->prefixbuf, cmd->prefixbuflen);
    ptr = idns_cmdenc_buf(ptr, cmd->token, 16);
    ptr = idns_cmdenc_2byte(ptr, cmd->valuetype);
    ptr = idns_cmdenc_2byte(ptr, cmd->valuelen);
    ptr = idns_cmdenc_buf(ptr, cmd->valuebuf, cmd->valuelen);
    int len = ptr - sendbuf;
    return len;
}