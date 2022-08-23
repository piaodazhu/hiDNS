#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "prefixtrie.h"

int
_get_next_componentlen(const unsigned char *name, int len, int *offset)
{
	if (*offset >= len)
		return 0;
	if (name[*offset] == '/') 
		*offset = *offset + 1;
	int curpos = *offset;
	while (curpos < len && name[curpos] != '/') {
		++curpos;
	}
	return curpos - *offset;
}

prefix_trie_t*
prefix_trie_init(const unsigned char *zonename, unsigned int zlen)
{
	return prefix_trienode_new(zonename, zlen);
}


void
prefix_trie_destroy(prefix_trie_t *root)
{
	prefix_trienode_purge(root, NULL, 0, NULL, NULL);
	return;
}


prefix_trie_t*
prefix_trienode_new(const unsigned char *component, unsigned int clen)
{
	prefix_trienode_t *node = (prefix_trienode_t*) malloc(sizeof(prefix_trienode_t));
	node->hasrecord = 0;
	node->reserved = 0;
	node->componentlen = clen;
	node->childrencount = 0;
	node->_activerecord = 0;
	node->component = malloc(clen);
	memcpy(node->component, component, clen);
	node->children = NULL;
	node->brother = NULL;
	return node;
}



void
prefix_trienode_free(prefix_trienode_t *node)
{
	if (node->component != NULL)
		free(node->component);
	free(node);
}

trienode_queue_item_t*
prefix_trieqitem_new(const prefix_trienode_t *node, 
	const unsigned char *previousprefix, unsigned int pplen)
{
	if (node == NULL)
		return NULL;
	trienode_queue_item_t *item = (trienode_queue_item_t*) malloc(sizeof(trienode_queue_item_t));
	item->node = (prefix_trienode_t*)node;
	item->next = NULL;
	item->prefixlen = pplen;
	memcpy(item->prefixbuf, previousprefix, pplen);
	return item;
}


void prefix_trieqitem_free(trienode_queue_item_t *item)
{
	prefix_trienode_free(item->node);
	free(item);
}

prefix_trie_t*
prefix_trienode_get(const prefix_trie_t *root, 
	const unsigned char *prefix, unsigned int plen)
{
	if (root->zoneprefixlen > plen || memcmp(root->zonename, prefix, root->zoneprefixlen) != 0)
		return NULL;
	
	int idx, clen;
	prefix_trienode_t *node;
	idx = root->zoneprefixlen;
	node = (prefix_trienode_t*)root;
	while ((clen = _get_next_componentlen(prefix, plen, &idx)) != 0) {
		node = node->children;
		while (node != NULL) {
			if (node->componentlen == clen && memcmp(node->component, prefix + idx, clen) == 0) {
				break;
			}
			node = node->brother;
		}
		if (node == NULL)
			return NULL;
		idx += clen;
	}
	return node;
}



int
prefix_trienode_put(prefix_trie_t *root, 
	const unsigned char *prefix, unsigned int plen)
{
	if (root->zoneprefixlen > plen || memcmp(root->zonename, prefix, root->zoneprefixlen) != 0)
		return -1;
	
	int idx, clen;
	prefix_trienode_t *node, *pre;
	idx = root->zoneprefixlen;
	node = root;
	pre = node;
	while ((clen = _get_next_componentlen(prefix, plen, &idx)) != 0) {
		pre = node;
		node = node->children;
		if (node == NULL)
			goto add_child;
		while (node != NULL) {
			// printf("node = %.*s <--> curr = %.*s\n", node->componentlen, node->component, clen, prefix + idx);
			if (node->componentlen == clen && memcmp(node->component, prefix + idx, clen) == 0) {
				++node->_activerecord;
				// printf("%.*s --> %d\n", clen, prefix + idx, node->_activerecord);
				break;
			}
			pre = node;
			node = node->brother;
		}
		if (node == NULL) {
			pre->brother = prefix_trienode_new(prefix + idx, clen);
			pre = pre->brother;
			idx += clen;
			goto add_child;
		}
		idx += clen;
	}
	node->hasrecord = 1;
	return 0;
add_child:
	while ((clen = _get_next_componentlen(prefix, plen, &idx)) != 0) {
		pre->children = prefix_trienode_new(prefix + idx, clen);
		pre = pre->children;
		idx += clen;
	}
	pre->hasrecord = 1;
	return 0;
}

trienode_queue_t* prefix_trienode_mkqueue(prefix_trie_t *root, 
	const unsigned char *previousprefix, unsigned int pplen)
{
	trienode_queue_t *queue, *qfront, *qrear;
	prefix_trienode_t *node, *child;
	queue = prefix_trieqitem_new(root, previousprefix, pplen);
	qfront = queue;
	qrear = queue;

	while (qfront != NULL) {
		node = qfront->node;
		child = node->children;
		while (child != NULL) {
			qrear->next = prefix_trieqitem_new(child, qfront->prefixbuf, qfront->prefixlen);
			qrear = qrear->next;

			memcpy(qrear->prefixbuf + qrear->prefixlen, child->component, child->componentlen);
			qrear->prefixlen += child->componentlen;
			qrear->prefixbuf[qrear->prefixlen++] = '/';

			child = child->brother;
		}
		qfront = qfront->next;
	}
	return queue;
}

void prefix_trienode_rmqueue(trienode_queue_t* queue)
{
	trienode_queue_item_t *pre, *next;
	pre = queue;
	while (pre != NULL) {
		next = pre->next;
		free(pre);
		pre = next;
	}
}


prefix_trie_t*
prefix_trienode_pop(prefix_trie_t *root, 
	const unsigned char *prefix, unsigned int plen)
{
	if (plen == 0 && prefix == NULL) {
		return root;
	}
	if (root->zoneprefixlen > plen || memcmp(root->zonename, prefix, root->zoneprefixlen) != 0)
		return NULL;
	
	int idx, clen;
	prefix_trienode_t *node, *pre;
	idx = root->zoneprefixlen;
	node = root;
	pre = node;
	while ((clen = _get_next_componentlen(prefix, plen, &idx)) != 0) {
		pre = node;
		node = node->children;
		while (node != NULL) {
			if (node->componentlen == clen && memcmp(node->component, prefix + idx, clen) == 0) {
				break;
			}
			pre = node;
			node = node->brother;
		}
		if (node == NULL)
			return NULL;
		idx += clen;
	}
	if (node == pre->children) {
		pre->children = node->brother;
	}
	else if (node == pre->brother) {
		pre->brother = node->brother;
	}
	else {
		perror("[ERROR] prefix trie wrong!\n");
	}
	return node;
}


void
prefix_trienode_purge(prefix_trie_t *root, 
	const unsigned char *prefix, unsigned int plen,
	void (*cb)(const prefix_trienode_t *node, 
		const unsigned char *prefix, unsigned int plen,
		void *args), void *arg)
{
	prefix_trienode_t *target = prefix_trienode_pop(root, prefix, plen);
	if (target == NULL) return;
	trienode_queue_t *qu, *qptr, *pre;
	qu = prefix_trienode_mkqueue(target, prefix, plen);
	qptr = qu;
	pre = qu;
	while (qptr != NULL) {
		if (cb != NULL)
			cb(qptr->node, qptr->prefixbuf, qptr->prefixlen, arg);
		pre = qptr;
		qptr = qptr->next;
		prefix_trieqitem_free(pre);
	}
}



void
prefix_trie_visit(prefix_trie_t *root, 
	void (*cb)(const prefix_trienode_t *node, 
		const unsigned char *prefix, unsigned int plen,
		void *args), void *arg)
{
	trienode_queue_t *qu, *qptr;
	qu = prefix_trienode_mkqueue(root, root->zonename, root->zoneprefixlen);
	qptr = qu;
	while (qptr != NULL) {
		if (cb != NULL)
			cb(qptr->node, qptr->prefixbuf, qptr->prefixlen, arg);
		qptr = qptr->next;
	}
	prefix_trienode_rmqueue(qu);
}

void cb_printnode(const prefix_trienode_t *node, 
		const unsigned char *prefix, unsigned int plen,
		void *args)
{
	if (node->hasrecord == 1) {
		printf("prefix: %.*s, activity = %u\n", plen, prefix, node->_activerecord);
	}
}

void cb_dumpnode(const prefix_trienode_t *node, 
		const unsigned char *prefix, unsigned int plen,
		void *args)
{
	if (node->hasrecord == 1) {
		dumpbuf_t *dbuf = args;
		if (dbuf->curlen + 1 + plen <= dbuf->totlen) {
			dbuf->buffer[dbuf->curlen++] = plen;
			memcpy(dbuf->buffer + dbuf->curlen, prefix, plen);
			dbuf->curlen +=  plen;
			++dbuf->totcnt;
		}
	}
}


unsigned int
prefix_trie_dump(const prefix_trie_t *root, const char *filename)
{
	dumpbuf_t *dbuf = dumpbuf_new(1024 * 1024 * 16);
	
	// first.  save zone infos
	dbuf->buffer[dbuf->curlen++] = root->zoneprefixlen;
	memcpy(dbuf->buffer + dbuf->curlen, root->zonename, root->zoneprefixlen);
	dbuf->curlen += root->zoneprefixlen;

	// second. save every prefix
	prefix_trie_visit((prefix_trie_t*)root, cb_dumpnode, (void*)dbuf);
	unsigned int ret = dbuf->totcnt;

	// third. dump to file
	dumpbuf_dump(dbuf, filename);
	dumpbuf_free(dbuf);
	return ret;
}


prefix_trie_t*
prefix_trie_load(const char *filename)
{
	// first. load from file
	dumpbuf_t *dbuf = dumpbuf_new(1024 * 1024 * 16);
	unsigned int len = dumpbuf_load(dbuf, filename);
	if (len <= 0) {
		return NULL;
	}

	unsigned char *ptr = dbuf->buffer;
	unsigned char *bound = dbuf->buffer + dbuf->curlen;
	// second. get zone infos.
	prefix_trie_t *root = prefix_trie_init(ptr + 1, *ptr);
	ptr += (*ptr + 1);
	// third. put all prefixes.
	while (ptr < bound) {
		if (prefix_trienode_put(root, ptr + 1, *ptr) != 0) {
			prefix_trie_destroy(root);
			dumpbuf_free(dbuf);
			return NULL;
		}
		ptr += (*ptr + 1);
	}
	dumpbuf_free(dbuf);
	return root;
}

dumpbuf_t* dumpbuf_new(unsigned int size)
{
	dumpbuf_t *dbuf = (dumpbuf_t*)malloc(sizeof(dumpbuf_t));
	dbuf->buffer = malloc(size);
	dbuf->totlen = size;
	dbuf->curlen = 0;
	dbuf->totcnt = 0;
	return dbuf;
}

void dumpbuf_free(dumpbuf_t *dbuf)
{
	if (dbuf->buffer != NULL)
		free(dbuf->buffer);
	free(dbuf);
}

void dumpbuf_dump(const dumpbuf_t *dbuf, const char *filename)
{
	FILE *fp = fopen(filename, "wb");
	fwrite(dbuf->buffer, 1, dbuf->curlen, fp);
	fclose(fp);
}

unsigned int dumpbuf_load(dumpbuf_t *dbuf, const char *filename)
{
	FILE *fp = fopen(filename, "rb");
	if (fp == NULL) {
		return 0;
	}
	unsigned int len = fread(dbuf->buffer, 1, dbuf->totlen, fp);
	fclose(fp);
	if (len == dbuf->totlen) {
		return 0;
	}
	dbuf->curlen = len;
	return len;
}