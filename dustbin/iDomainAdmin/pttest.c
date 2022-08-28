#include "idns_pt.h"

clientcommand_t cmd[10];

char str[][48] = {"/edu/bit/lab1/", "/edu/bit/lab2/","/edu/bit/lab1/news/","/edu/bit/lab1/papers/",
"/edu/bitlab/lab1/","/edu/mit/lab1/","/edu/bit/lab3/hello/test/", "/edu/bit/lab1/news/2021/",
"/edu/bit/lab1/news/2021/storage1/","/edu/bit/lab1/news/2019/"};

void cmdinit(clientcommand_t* cmd, u_int64_t idx)
{
	cmd->entity_id = 101;
	cmd->prefixbuf = malloc(64);
	cmd->prefixbuflen = sprintf(cmd->prefixbuf, "%s", str[idx]);
	memset(cmd->token, 0, 16);
	cmd->token[15] = 30 - idx;
	return;
}

int main() {
	prefix_tree_node_t* root = prefix_tree_init();
	int i;
	for (i = 0; i < 10; i++) {
		cmdinit(&cmd[i], i);
	}
	char ch;
	int ret = 1;
	while (ch = getchar()) {
		if (ch == '+') {
			ch = getchar();
			ret = prefix_tree_checkprefix(root, &cmd[ch - '0']);
			prefix_tree_node_insert(root, &cmd[ch - '0']);
		} else if (ch == '-') {
			ch = getchar();
			ret = prefix_tree_checkprefix(root, &cmd[ch - '0']);
			prefix_tree_node_delete(root, &cmd[ch - '0']);
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
	}
	return 0;
}

// void cmdinit(clientcommand_t* cmd, u_int64_t idx)
// {
//         cmd->entity_id = entity_id;
//         cmd->prefixbuf = malloc(64);
//         cmd->prefixbuflen = sprintf(cmd->prefixbuf, "prefix%ld", entity_id);
//         return;
// }

// void *t1(void* arg) {
//         prefix_register_entry_t* prt = (prefix_register_entry_t*) arg;
//         prefix_register_entry_t* ptr;
//         int i, ret;
//         for (i = 0; i < 10000;i++) {
//                 ret = prefix_register_entry_delete(prt, &cmd[(i * 997) % 10]);
//                 prefix_register_table_print(prt);
//                 usleep(50000);
//         }
//         //prefix_register_table_print(prt);
// }

// void *t2(void* arg) {
//         prefix_register_entry_t* prt = (prefix_register_entry_t*) arg;
//         prefix_register_entry_t* ptr;
//         int i, ret;
//         for (i = 0; i < 10000;i++) {
//                 ret = prefix_register_entry_insert(prt, &cmd[(i * 89) % 10]);
//                 prefix_register_table_print(prt);
//                 usleep(50000);
//         }
//         //prefix_register_table_print(prt);
// }

// int main()
// {       
//         int i;
//         for (i = 0; i < 10; i++) {
//                 cmdinit(&cmd[i], i);
//         }
//         cmd[9].prefixbuflen -= 1;
//         for (i = 0; i < 10; i++) {
//                 node[i] = prefix_register_entry_alloc(&cmd[i]);
//         }

//         prefix_register_entry_t* ptr;
//         prefix_register_entry_t* prt = prefix_register_table_init();
//         prefix_register_table_print(prt);

//         // prefix_register_entry_insert(prt, node[0]);
//         // prefix_register_table_print(prt);

//         // prefix_register_entry_insert(prt, node[3]);
//         // prefix_register_table_print(prt);

//         // prefix_register_entry_insert(prt, node[6]);
//         // prefix_register_table_print(prt);

//         // // prefix_register_entry_delete(node[0]);
//         // // prefix_register_table_print(prt);

//         // prefix_register_entry_insert(prt, node[9]);
//         // prefix_register_table_print(prt);

//         // // prefix_register_entry_delete(node[6]);
//         // // prefix_register_table_print(prt);

//         // ptr = prefix_register_table_findprefix(prt, &cmd[6]);
//         // ptr = prefix_register_table_findprefix(prt, &cmd[7]);
//         // ptr = prefix_register_table_findprefix(prt, &cmd[8]);
//         // ptr = prefix_register_table_findprefix(prt, &cmd[0]);

//         // prefix_register_entry_delete(ptr);
//         // prefix_register_table_print(prt);

//         pthread_t tid1, tid2;
//         pthread_create(&tid2, NULL, t2, (void*)prt);
//         pthread_create(&tid1, NULL, t1, (void*)prt);

//         pthread_join(tid1, NULL);
//         pthread_join(tid2, NULL);
//         return 0;
// }
