#include <sys/socket.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/isockethdr.h>
#include "nipsock.h"
#include "command.h"

char* proxyprefix = "/local/prproxy/n1";
char* bindprefix = "/edu/bit/lab1";
char* protocol = "iNPRP";
char token[16]={0x00, 0x00, 0x00, 0x00, 
                0x00, 0x00, 0x00, 0x00, 
                0x00, 0x00, 0x00, 0x00, 
                0x00, 0x00, 0x10, 0x38};

int main(int argc, char *argv[])
{
    char *prefix_with_splash = malloc(1024);
    int plen_with_splash;
    int plen;

    if (argc != 3 || strlen(argv[1]) != 1 || (argv[1][0] != '+' && argv[1][0] != '-')) {
        printf("[x] input error. usage: client [+-] {prefix}\n");
        exit(0);
    }
    else {
        plen = strlen(argv[2]);
        memcpy(prefix_with_splash, argv[2], plen);
        if (argv[2][plen - 1] == '/') {
            plen_with_splash = plen;
            --plen;
        } else {
            plen_with_splash = plen + 1;
            prefix_with_splash[plen] = '/';
        }
    }

    int sock = iSocket(AF_NNET, SOCK_NDP, htons(ETH_P_NIP));
    struct nsockaddr addr;
    addr.family = AF_NNET;
    addr.enable_mask = BIND_PREFIX;
    addr.prefix = bindprefix;  
    addr.plen = strlen(bindprefix);
    iBind(sock, &addr, sizeof(addr));

    char registername[1024];
    char infoname[1024];
    char infodata[1024];
    char certname[1024]; 
    char certdata[1024];
    char statusname[1024];
    char statusdata[1024];
    time_t ts = time(NULL);

    clientcommand_t* cmd = idns_cmdmem_init();    
    cmd->entity_id = 12;
    cmd->opcode = argv[1][0]=='+'?IDNS_CMD_OPCODE_ADD:IDNS_CMD_OPCODE_DEL;
    cmd->prefixbuflen = plen_with_splash;
    cmd->prefixbuf = prefix_with_splash;
    cmd->prefixexpiretime = 86400;
    cmd->timestamp = ts;
    memcpy(cmd->token, token, 16);
    
    int registername_len = sprintf(registername, "%s/%s/register%.*s%ld", proxyprefix, protocol, plen_with_splash, prefix_with_splash, ts);
    int statusname_len = sprintf(statusname, "%s/%s/status%.*s%ld", proxyprefix, protocol, plen_with_splash, prefix_with_splash, ts);
    int infoname_len = sprintf(infoname, "%.*s%s/info/%ld", plen_with_splash, prefix_with_splash, protocol, ts);
    int infodata_len = idns_cmdenc_cmd(cmd, 1024, infodata);
    int certname_len = sprintf(certname, "%.*s%s/cert/%ld", plen_with_splash, prefix_with_splash, protocol, ts);
    int certdata_len = sprintf(certdata, "my cert");
    
    struct isockbuf *infobuf = ibuf_data_init(infoname, infoname_len, infodata, infodata_len, IBUF_REF_NAME|IBUF_REF_DATA);
    struct isockbuf *certbuf = ibuf_data_init(certname, certname_len, certdata, certdata_len, IBUF_REF_NAME|IBUF_REF_DATA);
    iPublish(sock, infobuf, sizeof(struct isockbuf));
    iPublish(sock, certbuf, sizeof(struct isockbuf));

    struct touch_info *tinfo = ibuf_tinfo_init(registername, registername_len, IBUF_REF_NAME);
    struct isockbuf *rbuf = ibuf_data_init(registername, registername_len, NULL, 1024, IBUF_REF_NAME|IBUF_COPY_DATA);
    iTouch(sock, tinfo, sizeof(struct touch_info), 0);
    iRequest(sock, tinfo, tinfo->__realsize);
	iRecv(sock, rbuf, sizeof(struct isockbuf), 0);
    printf("[+] recv regster respond: %.*s\n", rbuf->dlen, rbuf->data);
    
    // printf("[+] waiting 1s for prefix register status...\n");
    // sleep(1);

    ibuf_tinfo_reset(tinfo, statusname_len, statusname);
    struct isockbuf *sbuf = ibuf_data_init(statusname, statusname_len, NULL, 1024, IBUF_REF_NAME|IBUF_COPY_DATA);
	iTouch(sock, tinfo, tinfo->__realsize, 0);
	iRequest(sock, tinfo, tinfo->__realsize);
	iRecv(sock, sbuf, sizeof(struct isockbuf), 0);

    switch(sbuf->data[0]) {
    case IDNS_RCODE_SUCCEED_ADD: printf("[v] register succeed.\n"); break;
    case IDNS_RCODE_SUCCEED_UPDATE: printf("[v] update succeed.\n"); break;
    case IDNS_RCODE_SUCCEED_DEL: printf("[v] delete succeed.\n"); break;
    case IDNS_RCODE_ALREADY_DEL: printf("[-] prefix not found.\n"); break;
    case IDNS_RCODE_INVALID_PACKET: printf("[x] invalid register info.\n"); break;
    case IDNS_RCODE_INVALID_PREFIX: printf("[x] invalid public prefix.\n"); break;
    case IDNS_RCODE_INVALID_TIMESTAMP: printf("[x] invalid timestamp.\n"); break;
    case IDNS_RCODE_INVALID_OPCODE: printf("[x] invalid operation code.\n"); break;
    case IDNS_RCODE_INVALID_VALUETYPE: printf("[x] invalid value type.\n"); break;
    case IDNS_RCODE_UNAUTH_PACKET: printf("[x] refuse unauth entity.\n"); break;
    case IDNS_RCODE_UNAUTH_OP: printf("[x] refuse unauth operation.\n"); break;
    default: printf("[x] unknown prefix status.\n"); break;
    }

    ibuf_tinfo_free(tinfo, IBUF_REF_NAME);
    ibuf_data_free(infobuf, IBUF_REF_NAME|IBUF_REF_DATA);
    ibuf_data_free(certbuf, IBUF_REF_NAME|IBUF_REF_DATA);
    ibuf_data_free(rbuf, IBUF_REF_NAME|IBUF_COPY_DATA);
    ibuf_data_free(sbuf, IBUF_REF_NAME|IBUF_COPY_DATA);

    return 0;
}
