#ifndef PREFIX_TRIE
#define PREFIX_TRIE

typedef struct prefix_trie prefix_trie_t;
typedef struct prefix_trie prefix_trienode_t;
typedef struct trienode_queue_item trienode_queue_t;
typedef struct trienode_queue_item trienode_queue_item_t;

struct prefix_trie {
	unsigned char		hasrecord;
	union {
		unsigned char	componentlen;
		unsigned char	zoneprefixlen;
	};
	unsigned short		reserved;
	unsigned int		childrencount;
	unsigned int		_activerecord;
	union {
		char*		component;
		char*		zonename;
	};
        prefix_trienode_t*	children;
	prefix_trienode_t*	brother;
};

struct trienode_queue_item {
	prefix_trienode_t*	node;
	trienode_queue_item_t*	next;
	unsigned int		prefixlen;
	char			prefixbuf[256];
};

prefix_trie_t* prefix_trie_init(const unsigned char *zonename, unsigned int zlen);
void prefix_trie_destroy(prefix_trie_t *root);
prefix_trienode_t* prefix_trienode_new(const unsigned char *component, unsigned int clen);
void prefix_trienode_free(prefix_trienode_t *node);
trienode_queue_item_t* prefix_trieqitem_new(const prefix_trienode_t *node, 
	const unsigned char *previousprefix, unsigned int pplen);
void prefix_trieqitem_free(trienode_queue_item_t *item);

prefix_trie_t* prefix_trienode_get(const prefix_trie_t *root, 
	const unsigned char *prefix, unsigned int plen);
int prefix_trienode_put(prefix_trie_t *root, 
	const unsigned char *prefix, unsigned int plen);
prefix_trie_t* prefix_trienode_pop(prefix_trie_t *root, 
	const unsigned char *prefix, unsigned int plen);

trienode_queue_t* prefix_trienode_mkqueue(prefix_trie_t *root, 
	const unsigned char *previousprefix, unsigned int pplen);
void prefix_trienode_rmqueue(trienode_queue_t* queue);
void prefix_trienode_purge(prefix_trie_t *root, 
	const unsigned char *prefix, unsigned int plen,
	void (*cb)(const prefix_trienode_t *node, 
		const unsigned char *prefix, unsigned int plen,
		void *args), void *arg);
void prefix_trie_visit(prefix_trie_t *root, 
	void (*cb)(const prefix_trienode_t *node, 
		const unsigned char *prefix, unsigned int plen,
		void *args), void *arg);

void cb_printnode(const prefix_trienode_t *node, 
		const unsigned char *prefix, unsigned int plen,
		void *args);
void cb_dumpnode(const prefix_trienode_t *node, 
		const unsigned char *prefix, unsigned int plen,
		void *args);

unsigned int prefix_trie_dump(const prefix_trie_t *root, const char *filename);
prefix_trie_t* prefix_trie_load(const char *filename);

struct dumpbuf {
	unsigned char*		buffer;
	unsigned int		curlen;
	unsigned int		totlen;
	unsigned int		totcnt;
};
typedef struct dumpbuf dumpbuf_t;

dumpbuf_t* dumpbuf_new(unsigned int size);
void dumpbuf_free(dumpbuf_t *dbuf);
void dumpbuf_dump(const dumpbuf_t *dbuf, const char *filename);
unsigned int dumpbuf_load(dumpbuf_t *dbuf, const char *filename);

#endif