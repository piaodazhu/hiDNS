#include "idns_aof.h"
#include "globalconfig.h"

clientcommand_t cmd[10];

char str[][48] = {"/edu/bit/lab1/", "/edu/bit/lab2/","/edu/bit/lab1/news/","/edu/bit/lab1/papers/",
"/edu/bitlab/lab1/","/edu/mit/lab1/","/edu/bit/lab3/hello/test/", "/edu/bit/lab1/news/2021/",
"/edu/bit/lab1/news/2021/storage1/","/edu/bit/lab1/news/2019/"};

void cmdinit(clientcommand_t* cmd, u_int64_t idx)
{
	cmd->entity_id = 101;
	cmd->prefixbuf = malloc(64);
	cmd->prefixbuflen = sprintf(cmd->prefixbuf, "%s", str[idx]);
    cmd->prefixexpiretime = 9999;
	memset(cmd->token, 0x10, 16);
	cmd->token[15] = 30 - idx;
	return;
}

int main() {
	prefix_tree_node_t* root = prefix_tree_init();
    idns_aof_init("aoftest.idns", strlen("aoftest.idns"));
    idns_aof_load(root);
    prefix_tree_print(root);
	int i;
	for (i = 0; i < 10; i++) {
		cmdinit(&cmd[i], i);
	}
	char ch;
    char encbuf[1024];
	int ret = 1;
    int len = 0;
	while (ch = getchar()) {
		if (ch == '+') {
			ch = getchar();
			ret = prefix_tree_checkprefix(root, &cmd[ch - '0']);
			prefix_tree_node_insert(root, &cmd[ch - '0']);

            len = idns_cmdenc_cmd(&cmd[ch - '0'], 1024, encbuf);
            idns_aof_append(encbuf, len);
		} else if (ch == '-') {
			ch = getchar();
			ret = prefix_tree_checkprefix(root, &cmd[ch - '0']);
			prefix_tree_node_delete(root, &cmd[ch - '0']);

            len = idns_cmdenc_cmd(&cmd[ch - '0'], 1024, encbuf);
            idns_aof_append(encbuf, len);
		} else if (ch == 'r') {
            idns_aof_rewrite(root);
            ret = 1;
        }
		getchar();
		switch (ret) {
		case 0: printf("prefix doesn't exist, but is authenticated\n"); break;
		case -1: printf("prefix exists, and is authenticated\n"); break;
		case -2: printf("prefix is unauthenticated\n"); break;
		case -3: printf("prefix is not leaf, but is authenticated\n"); break;
		case -4: printf("prefix is invalid\n"); break;
		case -5: printf("prefix is not leaf, but is unauthenticated\n"); break;
		}
        prefix_tree_print(root);
        printf("\n\n");
	}
	return 0;
}