#include <sys/socket.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <ins_resolv.h>
#include "nipsock.h"
#include "ipsock.h"
#include "updatemsgtools.h"
#include "iPrefixRegisterProxyConfig.h"
#include "ins_verifysync.h"

hidns_update_msg request;
hidns_update_msg reply;
int doverify = 1;

#define IPRP_PREFIX_STATUS_OK   0x10
#define IPRP_PREFIX_STATUS_UNAUTH   0x11
#define IPRP_PREFIX_STATUS_PROCESSING   0x12


int inprp_extract_interest(char* name, int nlen, char* prefix, int *plen, time_t* ts)
{
	int lastsplit = strlen(LOCAL_PREFIX) + strlen(PROTOCOL_TAG);
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

int find_server(struct sockaddr_in *server, char* prefix, int plen) 
{
	char buf[INS_PFXMAXSIZE];
	memcpy(buf, prefix, plen);
	buf[plen] = 0;
	
	struct sockaddr** serverlist = ins_getadminbyname(buf, HIDNS_SERVER_IP, 1, insprefix_count_components(prefix, plen));
	if (serverlist == NULL ) {
		return -1;
	}
	struct sockaddr** ptr = serverlist;
	while (*ptr != NULL) {
		if (*ptr->sa_family == AF_INET) {
			memcpy((unsigned char*)server, (unsigned char*)(*ptr), sizeof(struct sockaddr_in));
			ins_free_sockaddrlist(serverlist);
			return 0;
		}
	}
	ins_free_sockaddrlist(serverlist);
	return -1;
}

int main()
{
	int nipsock,ipsock;
	printf("[+] listen on local prefix: %s \n", LOCAL_PREFIX);
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
			int rcode;
			int nlen = sprintf(infoname, "%.*siNPRP/info/%ld", plen, prefix, ts);
			ibuf_tinfo_reset(tinfo, nlen, infoname);
			iTouch(nipsock, tinfo, tinfo->__realsize, 0);
			iRequest(nipsock, tinfo, tinfo->__realsize);
			iRecv(nipsock, rcvbuf, sizeof(struct isockbuf), 0);
			
			memcpy(request.rawbuf, rcvbuf->data, rcvbuf->dlen);

			updatemsg_init(&reply);
			if (updatemsg_parse(&request) != 0 ||plen != request.cmd.rrprefixlen || (memcmp(prefix, request.cmd.rrprefixbuf, plen) != 0)) {
				updatemsg_set_rcode(&reply, CHECK_MSG_INVALIDPFX);
				printf("[x] register info is not compatible with name!\n");
				goto publish_status;
			}
			// 判断命令合法性
			int chk = check_updatemsg_request(&request);
			int vrf = 1;
			if (chk < 0) {
				updatemsg_set_rcode(&reply, chk);
				printf("[x] register info is not compatible with name!\n");
				goto publish_status;
			}
			else if (doverify != 0) {
				else if (chk == 0) {
					// verify cert
					vrf = verify_hidns_x509_cert(request.cert.valbuf, request.cert.length, VERIFY_REQ_ARGTYPE_CERT_DER);
				}
				else if (chk > 0) {
					// verify msg
					vrf = verify_hidns_nocert_cmd(request._tbsptr, request._tbsbuf, request.sig.signerpfx, request.sig.signerlen, request.sig.signature, request.sig.sigbuflen, request.sig.algorithm);
				}
			}
			if (vrf != 0) {
				updatemsg_set_rcode(&reply, CHECK_MSG_INVALIDSIG);
				printf("[x] command cannot be verified.\n");
				goto publish_status;
			}

			struct sockaddr_in server;
			if (find_server(&server, prefix, plen) != 0) {
				updatemsg_set_rcode(&reply, CHECK_MSG_INVALIDPFX);
				printf("[x] Cannot find a proper iDomainAdmin server\n");
				goto publish_status;
			}
			// use tls?
			ipsock = socket(AF_INET,SOCK_STREAM, 0);
			if (ipsock < 0) {
				updatemsg_set_rcode(&reply, CHECK_MSG_SERVERFAIL);
				printf("[x] Cannot create IP socket\n");
				goto publish_status;
			}
			if(connect(ipsock, (struct sockaddr*)&server, sizeof(struct sockaddr_in)) < 0) {
				updatemsg_set_rcode(&reply, CHECK_MSG_SERVERFAIL);
				close(ipsock);
				printf("[x] Cannot connect with iDomainAdmin server\n");
				goto publish_status;
			}
			if (request.cmd.rrtype == COMMAND_RRTYPE_A_TBF) {
				hidns_update_addition add;
				add.type = ADDITION_TYPE_A;
				add.length = strlen(LOCAL_IGATE_IP);
				add.valbuf = LOCAL_IGATE_IP;
				updatemsg_append_addition(&request, &add);
			}
			Write(ipsock, request.rawbuf, request.rawbuflen);
			int valid_reply = 0;
			if (Read(ipsock, reply.rawbuf, sizeof(reply.len_n)) == sizeof(reply.len_n)) {
				unsigned short len = ntohs(reply.len_n);
				if (Read(ipsock, reply.buf, len) == len) {
					if (updatemsg_parse(&reply) == 0 && check_updatemsg_ismatch(&request, &reply) == 0 && check_updatemsg_reply(&reply) >= 0) {
						valid_reply = 1;
					}
				}
			}
			if (valid_reply == 0) {
				updatemsg_init(&reply);
				updatemsg_set_rcode(&reply, CHECK_MSG_SERVERFAIL);
			}
			close(ipsock);
			printf("[v] Status data is prepared\n");
publish_status:
			databuf->nlen = sprintf(databuf->name, "%s/iNPRP/status%.*s%ld", LOCAL_PREFIX, plen, prefix, ts);
			databuf->dlen = reply.rawbuflen;
			memcpy(databuf->data, reply.rawbuf, reply.rawbuflen);
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
