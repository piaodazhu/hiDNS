#include "loadconf.h"
int main()
{
	char* testprefix[6] = {"/com/baidu/www/xxx", "/edu/bit/lab1/news/xx/123", "/icn/xxx/xxx",
				"/nip/xxx/xxx", "/xxx/xxx/xxx", "/icn/nip/xxxxx/xx"};
	load_conf_json("../config.json");
	int i = 0;
	for (i = 0; i < 6; i++) {

		ins_qry_buf qbuf;
		char *name = testprefix[i];
		qbuf.header.id = htons(1234);
		qbuf.header.rd = 1;
		qbuf.header.aa = 1;
		qbuf.header.hoplimit = 1;
		qbuf.header.reserved = 0;
		qbuf.header.maxcn = 5;
		qbuf.header.mincn = 3;
		qbuf.header.qtype = INS_T_A;
		qbuf.header.qnlen = strlen(name);
		memcpy(qbuf.buf + INS_QHEADERSIZE, name, strlen(name));
		int qlen = INS_QHEADERSIZE + strlen(name);

		printf ("[+] route %s to: ", testprefix[i]);
		rkt_route(0, testprefix[i], strlen(testprefix[i]), qbuf.buf, qlen);
		
		break;
	}

	return 0;
}

