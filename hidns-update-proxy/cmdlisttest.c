#include "eventcontext.h"

void printcmdbuf(session_cmdlist_t* cmd) {
	session_cmdlist_t *p = cmd;
	while (p) {
		printf("(fd=%d,id=%u), ", p->verify_fd, p->verify_id);
		p = p->next;
	}
	printf("(NULL)\n");
}

int main()
{
	user_epolldata_t udata;
	unsigned short id;
	hidns_update_command *cmd1 = updatemsg_new_command();
	hidns_update_command *cmd2 = updatemsg_new_command();
	hidns_update_command *cmd3 = updatemsg_new_command();
	hidns_update_command *cmd4;
	printcmdbuf(udata.ctx.cmdbuf);
	session_cmdlist_push(&udata.ctx, 2,12, cmd1);
	printcmdbuf(udata.ctx.cmdbuf);
	session_cmdlist_push(&udata.ctx, 3,13, cmd2);
	session_cmdlist_push(&udata.ctx, 4,14, cmd3);
	printcmdbuf(udata.ctx.cmdbuf);
	cmd4 = session_cmdlist_pop(&udata.ctx, 5, &id);
	if (cmd4 != NULL) return 1;
	cmd4 = session_cmdlist_pop(&udata.ctx, 3, &id);
	printf("cmd4: (%u %u)\n", cmd4->opcode, id);
	printcmdbuf(udata.ctx.cmdbuf);
	
	cmd4 = session_cmdlist_pop(&udata.ctx, 2, &id);
	printf("cmd4: (%u %u)\n", cmd4->opcode, id);
	printcmdbuf(udata.ctx.cmdbuf);

	cmd4 = session_cmdlist_pop(&udata.ctx, 4, &id);
	printf("cmd4: (%u %u)\n", cmd4->opcode, id);
	printcmdbuf(udata.ctx.cmdbuf);
	return 0;
}