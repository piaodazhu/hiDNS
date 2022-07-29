#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "prefixtrie.h"

int main()
{
	prefix_trie_t *root = prefix_trie_init("/icn/bit/", strlen("/icn/bit/"));
	printf("test init\n");
	prefix_trie_visit(root, cb_printnode, NULL);
	if (prefix_trienode_put(root, "/icn/bit/lab101/", strlen("/icn/bit/lab101/")) != 0) {
		return 0;
	}
	printf("test put\n");
	prefix_trie_visit(root, cb_printnode, NULL);
	if (prefix_trienode_put(root, "/icn/bit/lab/101/", strlen("/icn/bit/lab/101/")) != 0) {
		return 0;
	}
	if (prefix_trienode_put(root, "/icn/bit/lab/", strlen("/icn/bit/lab/")) != 0) {
		return 0;
	}
	if (prefix_trienode_put(root, "/icn/bit/lab101/101/", strlen("/icn/bit/lab101/101/")) != 0) {
		return 0;
	}
	if (prefix_trienode_put(root, "/icn/bt/lab101/101/", strlen("/icn/bt/lab101/101/")) == 0) {
		return 0;
	}
	if (prefix_trienode_put(root, "/icn/bit/lab101/1/2/3/4/", strlen("/icn/bit/lab101/1/2/3/4/")) != 0) {
		return 0;
	}
	if (prefix_trienode_put(root, "/icn/bit/lab101/1/2/3/", strlen("/icn/bit/lab101/1/2/3/")) != 0) {
		return 0;
	}
	if (prefix_trienode_put(root, "/icn/bit/lab101/1/2/3/4/5/", strlen("/icn/bit/lab101/1/2/3/4/5/")) != 0) {
		return 0;
	}
	if (prefix_trienode_put(root, "/icn/bit/lab101/1/2/3/4/x/", strlen("/icn/bit/lab101/1/2/3/4/x/")) != 0) {
		return 0;
	}
	printf("test put 2\n");
	prefix_trie_visit(root, cb_printnode, NULL);
	
	prefix_trienode_t *node = prefix_trienode_get(root, "/icn/bit/lab01/101/", strlen("/icn/bit/lab01/101/"));
	if (node != NULL) {
		return 0;
	}

	node = prefix_trienode_get(root, "/icn/bit/lab101/01/", strlen("/icn/bit/lab101/01/"));
	if (node != NULL) {
		return 0;
	}

	node = prefix_trienode_get(root, "/icn/bit/lab/", strlen("/icn/bit/lab/"));
	if (node == NULL) {
		return 0;
	}
	printf("test get\n%d\n", node->_activerecord);

	unsigned int ret = prefix_trie_dump(root, "trie.dump");
	printf("test dump\n%u\n", ret);

	node = prefix_trienode_pop(root, "/icn/bit/lab101/x/", strlen("/icn/bit/lab101/x/"));
	if (node != NULL) {
		return 0;
	}
	node = prefix_trienode_pop(root, "/icn/bit/lab101/", strlen("/icn/bit/lab101/"));
	if (node == NULL) {
		return 0;
	}
	printf("test pop\n%d\n", node->_activerecord);
	prefix_trie_visit(root, cb_printnode, NULL);

	prefix_trie_t* trie = prefix_trie_load("trie.dump");
	printf("test load\n");
	prefix_trie_visit(trie, cb_printnode, NULL);

	trienode_queue_t* qu = prefix_trienode_mkqueue(node, "/icn/bit/lab101/", strlen("/icn/bit/lab101/"));
	trienode_queue_item_t *ptr = qu;
	printf("test mkque\n");
	while (ptr != NULL) {
		printf("%.*s ---> %u\n", ptr->prefixlen, ptr->prefixbuf, ptr->node->_activerecord);
		ptr = ptr->next;
	}
	prefix_trienode_rmqueue(qu);
	
	prefix_trienode_purge(trie, "/icn/bit/lab101/", strlen("/icn/bit/lab101/"), NULL, NULL);

	printf("test purge\n");
	prefix_trie_visit(trie, cb_printnode, NULL);
	printf("test done!\n");
	return 0;
}