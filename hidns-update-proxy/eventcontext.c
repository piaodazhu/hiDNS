#include "eventcontext.h"

void
session_cmdlist_push(session_ctx_t *ctx, const int vrfd, const unsigned short vrid, hidns_update_command *cmd)
{
	if (cmd == NULL) return;
	session_cmdlist_t *session_cmdnode = (session_cmdlist_t*) malloc(sizeof(session_cmdlist_t));
	session_cmdnode->verify_fd = vrfd;
	session_cmdnode->verify_id = vrid;
	session_cmdnode->cmd = cmd;
	session_cmdnode->next = ctx->cmdbuf;
	ctx->cmdbuf = session_cmdnode;
	return;
}

hidns_update_command*
session_cmdlist_pop(session_ctx_t *ctx, const int vrfd, unsigned short *vrid)
{
	if (ctx->cmdbuf == NULL) return NULL;
	session_cmdlist_t *prev, *node;
	if (ctx->cmdbuf->verify_fd == vrfd) {
		node = ctx->cmdbuf;
		ctx->cmdbuf = node->next;
		node->next = NULL;
		*vrid = node->verify_id;
		return node->cmd;
	}
	prev = ctx->cmdbuf;
	node = prev->next;
	while (node != NULL) {
		if (node->verify_fd == vrfd) {
			prev->next = node->next;
			node->next = NULL;
			break;
		}
		prev = node;
		node = node->next;
	}
	if (node == NULL) {
		*vrid = 0;
		return NULL;
	}
	*vrid = node->verify_id;
	return node->cmd;
}
