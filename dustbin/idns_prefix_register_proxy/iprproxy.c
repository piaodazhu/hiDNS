#include <sys/socket.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include "nipsock.h"
#include "ipsock.h"
#include "command.h"
#include "globalconfig.h"

char *localprefix = "/local/prproxy/n1";
char *protocol = "/iNPRP";
char *inprp_register_prefix = "/local/prproxy/n1/iNPRP/register";
#define IPRP_PROXY_RCODE_OK    0x00
#define IPRP_PROXY_RCODE_BUSY  0x01
#define IPRP_PROXY_RCODE_INVALID_PREFIX 0x03
#define IPRP_PROXY_RCODE_INVALID_TIMESTAMP  0x04

#define IPRP_PREFIX_STATUS_OK   0x10
#define IPRP_PREFIX_STATUS_UNAUTH   0x11
#define IPRP_PREFIX_STATUS_PROCESSING   0x12

#define IPRP_REQUEST_REQISTER   0x20
#define IPRP_REQUEST_STATUS     0x21
#define IPRP_REQUEST_INVALID    0x22

int inprp_extract_interest(char* name, int nlen, char* prefix, int *plen, time_t* ts)
{
	int lastsplit = strlen(inprp_register_prefix);
	int curidx = lastsplit;
	int prefixoffset = curidx;
	while (++curidx < nlen) {
		if (name[curidx] == '/')
			lastsplit = curidx;
	}
	++lastsplit;
	*plen = lastsplit - prefixoffset;
	memcpy(prefix, name + prefixoffset, *plen);
	char ts_str[12];
	int ts_strlen = nlen - lastsplit;
	memcpy(ts_str, name + lastsplit, ts_strlen);
	ts_str[ts_strlen] = 0;
	*ts = atol(ts_str);
	return 0;
}

int check_register_prefix(char* prefix, int plen)
{
	if (plen > 256) return -1;
	int cur_componentlen = 0;
	int component_num = 0;
	int idx = 0;
	// example: /edu/bit/lab1/
	for (idx = 1; idx < plen; idx++) {
		if (prefix[idx] == '/') {
			if (cur_componentlen == 0 || cur_componentlen > 63) 
				return -3;
			++component_num;
			cur_componentlen = 0;
		}
		else if ((prefix[idx] >= '0' && prefix[idx] <= '9') 
				|| (prefix[idx] >= 'a' && prefix[idx] <= 'z') 
				|| prefix[idx] == '-')
		{
			++cur_componentlen;
		} 
		else {
			return -4;
		}
	}
	if (component_num > 8) 
		return -2;
	return 0;
}

int check_entity_id(uint64_t id) 
{
	// haven't implemented
	// return 0 if ok
	// return 1 if not found
	// return -1 if bad
	return 0;
}

int find_server(struct sockaddr_in *server, char* prefix, int plen) 
{
	// haven't implemented
	// example: /edu/bit/lab1/news/
	// 1 lookup news.lab1.bit.edu.
	// 2 lookup lab1.bit.edu.
	// 3 lookup bit.edu.
	// 4 lookup edu.

	// for test:
	server->sin_family = AF_INET;
	server->sin_port = htons(REMOTE_PORT);
	server->sin_addr.s_addr = inet_addr(TEST_DOMAIN_ADMIN);
	return 0;
}

int main()
{
	int nipsock,ipsock;
	printf("[+] listen on local prefix: %s \n", localprefix);
	int ip_sendlen, ip_rcvlen;
	char ip_sendbuf[2048];
	char ip_rcvbuf[2048];
	char infoname[1024];
	char info[1024];
	struct isockbuf* rcvbuf = ibuf_data_init(infoname, 1024, info, 1024, IBUF_REF_NAME|IBUF_REF_DATA);
	struct isockbuf* databuf = ibuf_data_init(NULL, 256, NULL, 64, IBUF_COPY_NAME|IBUF_COPY_DATA);
	struct status_info* stat_info = ibuf_sinfo_init(NULL, 1024, IBUF_COPY_NAME);
	struct touch_info* tinfo = ibuf_tinfo_init(NULL, 1024, IBUF_COPY_NAME);
	
	nipsock = iSocket(AF_NNET, SOCK_NDP, htons(ETH_P_NIP));
	struct nsockaddr addr;
	addr.family = AF_NNET;
	addr.enable_mask = BIND_PREFIX;
	addr.prefix = localprefix;  
	addr.plen   = strlen(localprefix);
	iBind(nipsock, &addr, sizeof(addr));

	int register_wid = iWatch(nipsock, inprp_register_prefix, strlen(inprp_register_prefix));

	while (iStatus(nipsock, stat_info, sizeof(struct status_info), 0)) {
		if (!stat_info->satisfied && stat_info->watch_id == register_wid) {
			// printf("[+] statu_info nlen: %d\n", stat_info->nlen);
			printf("[+] new registering request: %.*s \n", stat_info->nlen, stat_info->name_buf);
			char prefix[256];
			int plen;
			time_t curtime = time(NULL);
			time_t ts;
			stat_info->nlen -= 7; // 7: /_TOUCH
			
			databuf->name = stat_info->name_buf;
			databuf->nlen = stat_info->nlen;

			inprp_extract_interest(stat_info->name_buf, stat_info->nlen, prefix, &plen, &ts);

			// 判断前缀合法性
			// 判断时间戳有效性
			int isvalid = 1;
			if (curtime - ts > 10) {
				databuf->dlen = sprintf(databuf->data, "Bad TimeStamp");
				printf("[x] Bad TimeStamp\n");
				isvalid = 0;
			}
			else if (check_register_prefix(prefix, plen) < 0) {
				databuf->dlen = sprintf(databuf->data, "Bad Prefix");
				printf("[x] Bad Prefix\n");
				isvalid = 0;
			}
			else {
				databuf->dlen = sprintf(databuf->data, "OK");
			}

			iCast(nipsock, databuf, sizeof(struct isockbuf), 0);
			
			if (isvalid == 0) {
				goto statusbuf_reset;
			}
			// 处理事务
			int rcode = 0;
			clientcommand_t* cmd = idns_cmdmem_init();
			int nlen = sprintf(infoname, "%.*siNPRP/info/%ld", plen, prefix, ts);
			ibuf_tinfo_reset(tinfo, nlen, infoname);
			iTouch(nipsock, tinfo, tinfo->__realsize, 0);
			iRequest(nipsock, tinfo, tinfo->__realsize);
			iRecv(nipsock, rcvbuf, sizeof(struct isockbuf), 0);
			
			idns_cmddec_cmd(cmd, rcvbuf->dlen, rcvbuf->data);
			// 判断命令合法性
			if (cmd->timestamp != ts || plen != cmd->prefixbuflen || strncmp(prefix, cmd->prefixbuf, plen) != 0) {
				rcode = IDNS_RCODE_INVALID_PACKET;
				printf("[x] register info is not compatible with name!\n");
				goto publish_status;
			}
			if (cmd->opcode != IDNS_CMD_OPCODE_ADD && cmd->opcode != IDNS_CMD_OPCODE_DEL) {
				rcode = IDNS_RCODE_UNAUTH_OP;
				printf("[x] Invalid operation\n");
				goto publish_status;
			}
			if (check_entity_id(cmd->entity_id) > 0) {
				// fetch cert, update eit
			}
			if (check_entity_id(cmd->entity_id) < 0) {
				rcode = IDNS_RCODE_UNAUTH_OP;
				printf("[x] Unauth entity\n");
				goto publish_status;
			}

			struct sockaddr_in server;
			if (find_server(&server, prefix, plen) != 0) {
				rcode = IDNS_RCODE_INVALID_PREFIX;
				printf("[x] Cannot find a proper iDomainAdmin server\n");
				goto publish_status;
			}
			ipsock = socket(AF_INET,SOCK_STREAM, 0);
			if (ipsock < 0) {
				rcode = 0x98;
				printf("[x] Cannot create IP socket\n");
				goto publish_status;
			}
			if(connect(ipsock, (struct sockaddr*)&server, sizeof(struct sockaddr_in)) < 0) {
				rcode = 0x99;
				close(ipsock);
				printf("[x] Cannot connect with iDomainAdmin server\n");
				goto publish_status;
			}
			// 构造cmd
			// cmd->prefixexpiretime = min(cmd->prefixexpiretime, eit_get_expiretiem(eit, entity_id));
			cmd->entity_id = IDNS_ROOT_ENTITY_ID;
			cmd->valuetype = IDNS_CMD_VALUETYPE_A;
			cmd->valuelen = strlen(LOCAL_IGATE_IP);
			cmd->valuebuf = malloc(cmd->valuelen);
			memcpy(cmd->valuebuf, LOCAL_IGATE_IP, cmd->valuelen);
			ip_sendlen = idns_cmdenc_cmd(cmd, 2048, ip_sendbuf);
			write(ipsock, ip_sendbuf, ip_sendlen);
			ip_rcvlen = read(ipsock, ip_rcvbuf, 1024);
			close(ipsock);
			rcode = ip_rcvbuf[0];
			printf("[v] Status data is prepared\n");
publish_status:
			databuf->nlen = sprintf(databuf->name, "%s/iNPRP/status%.*s%ld", localprefix, plen, prefix, ts);
			databuf->dlen = 64;
			memset(databuf->data, 0x11, 64);
			databuf->data[0] = rcode;
			iPublish(nipsock, databuf, sizeof(struct isockbuf));
		}
statusbuf_reset:
		ibuf_data_reset(rcvbuf, 1024, 1024);
		ibuf_sinfo_reset(stat_info, 1024);
	}
	ibuf_data_free(rcvbuf, IBUF_REF_NAME|IBUF_REF_DATA);
	ibuf_data_free(databuf, IBUF_COPY_NAME|IBUF_COPY_DATA);
	ibuf_sinfo_free(stat_info, IBUF_COPY_NAME);
	ibuf_tinfo_free(tinfo, IBUF_COPY_NAME);
	close(nipsock);
	return 0;
}                 
