#include "idnsadmin.h"

prefix_tree_node_t* pt;
entity_info_entry_t* eit;

uint8_t manager_process(struct sockaddr_in remote, char* rcvbuf);

void *session_process(void *arg)
{
	struct session_args *sargs = (struct session_args*) arg;
	int sockfd = sargs->sockfd;
	struct sockaddr_in remote = sargs->remote;

	printf("\nget a client, ip:%s, port:%d\n",inet_ntoa(remote.sin_addr),ntohs(remote.sin_port));

	// idns register protocol
	// 接收第一个数据包
	#define NPRP_MAX_RCVBUF_LEN 2048
	//char *rcvbuf = (char*)malloc(NPRP_MAX_RCVBUF_LEN);
	char rcvbuf[NPRP_MAX_RCVBUF_LEN];
	char rcodebuf[64];//
	uint8_t rcode;
	int rcvlen = read(sockfd, rcvbuf, NPRP_MAX_RCVBUF_LEN);
	if (rcvlen <= 40 || rcvlen == NPRP_MAX_RCVBUF_LEN) 
	{
		printf("client is quit, or invalid packet!\n");
		goto error_out;
	}
	// 解析管理命令
	uint64_t entity_id;
	idns_cmddec_8byte(rcvbuf, &entity_id);
	if (entity_id == IDNS_ROOT_ENTITY_ID) {
		rcode = manager_process(remote, rcvbuf);
		memset(rcodebuf, 0x11, 64);
		rcodebuf[0] = rcode;
		write(sockfd, rcodebuf, 64);
		close(sockfd);
		printf("connection closed. rcode = %d\n...\n", rcode);
		pthread_exit(NULL);
	}
	// 解析注册请求
	clientcommand_t *cmd = idns_cmdmem_init();
	if (idns_cmddec_cmd(cmd, rcvlen, rcvbuf) < 0) {
		printf("invalid packet format!\n");
		rcode = IDNS_RCODE_INVALID_PACKET;
		goto process_out;
	}

	// 检查时间戳
	if (time(NULL) - cmd->timestamp > IDNS_TIMESTAMP_THRESHOLD) {
		printf("out-of-day packet!\n");
		rcode = IDNS_RCODE_INVALID_TIMESTAMP;
		goto process_out;
	}
	// 检查操作码
	if (cmd->opcode != IDNS_CMD_OPCODE_ADD && cmd->opcode != IDNS_CMD_OPCODE_DEL) {
		printf("operation hasn't implemented!\n");
		rcode = IDNS_RCODE_INVALID_OPCODE;
		goto process_out;
	}
	// 检查值类型
	if (cmd->valuetype > IDNS_CMD_VALUETYPE_CNAME) {
		printf("unsupported value type!\n");
		rcode = IDNS_RCODE_INVALID_VALUETYPE;
		goto process_out;
	}

	// 验证签名 (待实现)
	// 如果EIT表里有，直接验证数据包得到结果
	// 如果EIT表里没有：
	// 	1. 返回一个码用以获取证书
	//	2. 拆封证书
	//	3. 添加实体和公钥信息到EIT
	//	4. 验证数据包得到结果
	if (checksignature() != 0) {
		printf("invalid signature!\n");
		rcode = IDNS_RCODE_UNAUTH_PACKET;
		goto process_out;
	}
	// 根据opcode和前缀查询PT树
	int res;
	idns_updateinfo_t* uinfo = idns_rrup_updateinfo_alloc();
	
	if (cmd->opcode == IDNS_CMD_OPCODE_ADD) {
		printf("ok, start insert!\n");
		res = prefix_tree_checkprefix(pt, cmd) + 5;	// TBD: ugly code
		idns_rrup_updateinfo_set_opcode_add(uinfo);
try_to_insert:
		switch (res) {
		case 0: rcode = IDNS_RCODE_UNAUTH_OP; break;
		case 1: rcode = IDNS_RCODE_INVALID_PREFIX; break;
		case 3: rcode = IDNS_RCODE_UNAUTH_OP; break;
		default: {
			res = prefix_tree_node_insert(pt, cmd) + 5;
			if (res == 5) {
				// newly register a prefix
				idns_rrup_updateinfo_set_opcode_add(uinfo);
				idns_rrup_callback(cmd, uinfo);
				rcode = IDNS_RCODE_SUCCEED_ADD;
			} else if (res == 2 || res == 4) {
				// update a existed prefix
				idns_rrup_updateinfo_set_opcode_edit(uinfo);
				idns_rrup_callback(cmd, uinfo);			
				rcode = IDNS_RCODE_SUCCEED_UPDATE;
			} else {
				// if checkprefix is ok, but insert faild, means thread competition.
				// so try to insert until faild or succeed.
				goto try_to_insert;
			}
		}
		}
	} else {
		printf("ok, start delete!\n");
		res = prefix_tree_checkprefix(pt, cmd) + 5;	// TBD: ugly code
		idns_rrup_updateinfo_set_opcode_del(uinfo);
try_to_delete:
		switch (res) {
		case 0: rcode = IDNS_RCODE_UNAUTH_OP; break; // bug: also maybe already deleted...
		case 1: rcode = IDNS_RCODE_INVALID_PREFIX; break;
		case 3: rcode = IDNS_RCODE_UNAUTH_OP; break;
		case 5: rcode = IDNS_RCODE_ALREADY_DEL; break;
		default: {
			// TBD: difficult logic
			res = prefix_tree_node_delete_withcallback(pt, cmd, idns_rrup_callback, cmd, uinfo) + 5;
			if (res == 4)
				rcode = IDNS_RCODE_SUCCEED_DEL;
			else
				goto try_to_delete;
		}
		}
	}
	idns_rrup_updateinfo_free(uinfo);
process_out:
	// return code
	memset(rcodebuf, 0x11, 64);
	rcodebuf[0] = rcode;
	write(sockfd, rcodebuf, 64);
	idns_cmdmem_free(cmd);
error_out:
	close(sockfd);
	printf("connection closed. rcode = %d\n...\n", rcode);
	if (rcode == IDNS_RCODE_SUCCEED_ADD || rcode == IDNS_RCODE_SUCCEED_UPDATE || rcode == IDNS_RCODE_SUCCEED_DEL) {
		idns_aof_append(rcvbuf, rcvlen);
	}
	//free(rcvbuf);
	pthread_exit(NULL);
}

void idns_rrup_callback(void* arg1, void* arg2) {
	clientcommand_t* cmd = (clientcommand_t*)arg1;
	idns_updateinfo_t* uinfo = (idns_updateinfo_t*)arg2;
	printf("callback called!\n");
	idns_rrup_updateinfo_set_class(uinfo, cmd->valuetype);
	idns_rrup_updateinfo_set_ttl(uinfo, 86400); // TBD
	idns_rrup_updateinfo_set_value(uinfo, cmd->valuebuf, cmd->valuelen);
	idns_rrup_updateinfo_set_domainname(uinfo, cmd->prefixbuf, cmd->prefixbuflen);
	idns_rrup_update_rr(uinfo);
	return;
}

void idns_prefix_print_callback(void* arg1, void* arg2, void* arg3, void* arg4) 
{
    char *complete_prefix = (char*) arg2;
    int *complete_prefixlen = (int*) arg3;
    printf("[R] %.*s\n", *complete_prefixlen, complete_prefix);
}

uint8_t manager_process(struct sockaddr_in remote, char* rcvbuf)
{
	// haven't implemented, and not safe
	if (remote.sin_addr.s_addr != inet_addr("127.0.0.1")) {
		printf("receive invalid manager command\n");
		return 0x42;
	}
	printf("receive manager command\n");
	printf("---flush domain right now---\n");
	idns_rrup_flush();
	printf("---rewrite aof right now---\n");
	idns_aof_rewrite(pt);
	return 0x41;
}

int main()
{
	pt = prefix_tree_init();
	eit = entity_info_table_init();
	idns_rrup_lock_init();
	idns_aof_init("aof.ida", strlen("aof.ida"));
    idns_aof_load(pt);
	struct sockaddr_in local;
	local.sin_family = AF_INET;
	local.sin_port = htons(LOCAL_PORT);
	local.sin_addr.s_addr = inet_addr(LOCAL_IP);
	socklen_t len = sizeof(local);
	
	int connfd, listenfd;
	listenfd = TCPstart_up(&local, 100);

	struct sockaddr_in remote;
	socklen_t addrlen=sizeof(struct sockaddr);

	struct session_args sargs;
	pthread_t tid;

	int opcount = 0;
#ifdef PRINT_ZONE
		printf("\n++++++++list all+++++++++\n");
		prefix_tree_visit_withcallback(pt, idns_prefix_print_callback, NULL);
		printf("+++++++++++EOF+++++++++++\n\n");
#endif
	while (1)
	{
		connfd = Accept(listenfd,(struct sockaddr*)&remote, &addrlen);
		if (errno == EINTR) {
			continue;
		}
		sargs.remote = remote;
		sargs.sockfd = connfd;
		pthread_create(&tid, NULL, session_process, (void *)&sargs);
		pthread_detach(tid);//子线程分离，防止僵线程产生
#ifdef PRINT_ZONE
		sleep(1);
		printf("\n++++++++list all+++++++++\n");
		prefix_tree_visit_withcallback(pt, idns_prefix_print_callback, NULL);
		printf("+++++++++++EOF+++++++++++\n\n");
#endif
		opcount++;
		if (opcount % 10 == 0) {
			printf("---flush domain---\n");
			idns_rrup_flush();
			printf("---rewrite aof---\n");
			idns_aof_rewrite(pt);
		}
	}

	idns_rrup_lock_destroy();
	prefix_tree_destroy(pt);
	entity_info_table_destroy(eit);
	return 0;
}
