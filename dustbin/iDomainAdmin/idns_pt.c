#include "idns_pt.h"

pthread_rwlock_t pt_rwlock;

prefix_tree_node_t* 
prefix_tree_init()
{
        prefix_tree_node_t* root = (prefix_tree_node_t*)malloc(sizeof(prefix_tree_node_t));
        root->componentlen = strlen(PREFIX_TREE_ROOT);
        root->icn_component = malloc(root->componentlen);
        root->children_num = 0;
	root->entity_id = IDNS_ROOT_ENTITY_ID;
        // TBD
        memset(root->token, 0, 16);
        root->token[15] = IDNS_ROOT_TOKEN;
	memcpy(root->icn_component, PREFIX_TREE_ROOT, root->componentlen);
        root->parent = NULL;
        pthread_rwlock_init(&pt_rwlock, NULL);
#ifdef PT_DEBUG
        printf("PT: a trie initialized\n");
#endif
        return root;
}

prefix_tree_node_t* 
prefix_tree_node_alloc(unsigned int componentlen, char* component)
{
        prefix_tree_node_t* node = (prefix_tree_node_t*)malloc(sizeof(prefix_tree_node_t));
        node->children_num = 0;
	node->entity_id = 0;
        node->componentlen = componentlen;
        node->icn_component = malloc(componentlen);
        memcpy(node->icn_component, component, componentlen);
        node->parent = NULL;

        return node;
}

int 
prefix_tree_node_free(prefix_tree_node_t* node)
{
        free(node->icn_component);
        free(node);
        return 0;
}

prefix_tree_node_t* 
prefix_tree_findbyprefix(prefix_tree_node_t* root, 
                        unsigned int prefixbuflen, char* prefixbuf)
{
        pthread_rwlock_rdlock(&pt_rwlock);
        if (prefixbuflen <= root->componentlen 
                        || prefixbuf[0] != '/' 
                        || prefixbuf[prefixbuflen - 1] != '/') 
        {
                goto not_found;
        }

        int prefix_idx;
        unsigned int clen;
        unsigned int cidx;
        prefix_tree_node_t* node = root;
        int child_idx;

        for (prefix_idx = 0; prefix_idx < root->componentlen; prefix_idx++) {
                if (prefixbuf[prefix_idx] != root->icn_component[prefix_idx]) {
                        goto not_found;
                }
        }
        
        while (prefix_idx < prefixbuflen) {
                clen = 0;
                while (prefixbuf[prefix_idx + clen] != '/') ++clen;

                int found = 0;
                if (node->children_num == 0) {
                        goto not_found;
                }
                for (child_idx = 0; child_idx < node->children_num; child_idx++) {
                        
                        if (node->children[child_idx]->componentlen == clen) {
                                found = 1;
                                for (cidx = 0; cidx < clen; cidx++) {
                                        if (node->children[child_idx]->icn_component[cidx] != prefixbuf[prefix_idx + cidx]) {
                                                found = 0;
                                                break;
                                        }
                                }
                                if (found == 0) {
                                        continue;
                                }
                                else {
                                        node = node->children[child_idx];
                                        break;
                                }
                        }
                }
                if (found == 0) {
                        goto not_found;
                }
                prefix_idx = prefix_idx + clen + 1;
        }
        if (node->children_num == 0) {
                pthread_rwlock_unlock(&pt_rwlock);
                return node;
        }
not_found:
        pthread_rwlock_unlock(&pt_rwlock);
        return NULL;
}

int 
prefix_tree_checkprefix(prefix_tree_node_t* root, 
                        clientcommand_t* cmd)
{
        // before add, make sure this function return 0 or -1 or -3
        // before del, make sure this function return -1 or -3
        char *prefixbuf = cmd->prefixbuf;
        unsigned int prefixbuflen = cmd->prefixbuflen;   
        pthread_rwlock_rdlock(&pt_rwlock);
        // to record a deepest token along the tree
        char *token_record = root->token;
        if (prefixbuflen <= root->componentlen 
                        || prefixbuf[0] != '/' 
                        || prefixbuf[prefixbuflen - 1] != '/') 
        {
                goto invalid_prefix;
        }

        int prefix_idx;
        unsigned int clen;
        unsigned int cidx;
        prefix_tree_node_t* node = root;
        int child_idx;
        
        // the prefix must be under root
        for (prefix_idx = 0; prefix_idx < root->componentlen; prefix_idx++) {
                if (prefixbuf[prefix_idx] != root->icn_component[prefix_idx]) {
                        goto invalid_prefix;
                }
        }
        
        while (prefix_idx < prefixbuflen) {
		if (node->entity_id != 0) {
                        // every time finding a valid prefix, update token
			token_record = node->token;
		}
                if (node->children_num == 0) {
                        // like /edu/bit/lab101/news/ registering under /edu/bit/lab101/
                        goto tree_expand;
                }

                clen = 0;
                while (prefixbuf[prefix_idx + clen] != '/') ++clen;

                int found = 0;
                for (child_idx = 0; child_idx < node->children_num; child_idx++) {
                        
                        if (node->children[child_idx]->componentlen == clen) {
                                found = 1;
                                for (cidx = 0; cidx < clen; cidx++) {
                                        if (node->children[child_idx]->icn_component[cidx] != prefixbuf[prefix_idx + cidx]) {
                                                found = 0;
                                                break;
                                        }
                                }
                                if (found == 0) {
                                        continue;
                                }
                                else {
                                        node = node->children[child_idx];
					break;
                                }
                        }
                }
                if (found == 0) {
                        // like registering another prefix under /edu/bit/lab101/
                        goto tree_expand;
                }
                prefix_idx = prefix_idx + clen + 1;
        }
        if (node->entity_id == 0) {
                // prefix is exactly matched, so do EDIT or REJECT
                goto duplicate_name;
        }
        else {
                // prefix will be at non-leaf node
                goto non_leaf;
        }

tree_expand:
        if (!checktoken_hash128(cmd->token, token_record, 32)) {
		// prefix doesn't exist, and unauth
		pthread_rwlock_unlock(&pt_rwlock);
#ifdef PT_DEBUG
        printf("PT checkprefix: prefix doesn't exist, and unauth\n");
#endif
        	return -2;
	}

        // prefix doesn't exist, but authenticated
        pthread_rwlock_unlock(&pt_rwlock);
#ifdef PT_DEBUG
        printf("PT checkprefix: prefix doesn't exist, but authenticated\n");
#endif
        return 0;

invalid_prefix:
        pthread_rwlock_unlock(&pt_rwlock);
#ifdef PT_DEBUG
        printf("PT checkprefix: invalid prefix!\n");
#endif
        return -4;

duplicate_name:
        if (node->entity_id == cmd->entity_id && checktoken_hash128(cmd->token, node->token, 32)) {
                // prefix exists, and authenticated
		pthread_rwlock_unlock(&pt_rwlock);
#ifdef PT_DEBUG
        printf("PT checkprefix: prefix exists, and authenticated\n");
#endif
                return -1;
        }
        else {
                // prefix exists, but unauth
                pthread_rwlock_unlock(&pt_rwlock);
#ifdef PT_DEBUG
        printf("PT checkprefix: prefix exists, but unauth\n");
#endif
                return -2;
        }
non_leaf:
        if (node->entity_id == cmd->entity_id && checktoken_hash128(cmd->token, node->token, 32)) {
                // non leaf prefix exists, and authenticated
		pthread_rwlock_unlock(&pt_rwlock);
#ifdef PT_DEBUG
        printf("PT checkprefix: non leaf prefix exists, and authenticated\n");
#endif
                return -3;
        }
        else {
                // non leaf prefix exists, but unauth
                pthread_rwlock_unlock(&pt_rwlock);
#ifdef PT_DEBUG
        printf("PT checkprefix: on leaf prefix exists, and unauth\n");
#endif
                return -5;
        }
}

int
prefix_tree_node_insert(prefix_tree_node_t* root, 
                        clientcommand_t* cmd)
{
        char *prefixbuf = cmd->prefixbuf;
        unsigned int prefixbuflen = cmd->prefixbuflen;
        // to record a deepest token along the tree
        pthread_rwlock_wrlock(&pt_rwlock);
        char *token_record = root->token;
        if (prefixbuflen <= root->componentlen 
                        || prefixbuf[0] != '/' 
                        || prefixbuf[prefixbuflen - 1] != '/') 
        {
                goto invalid_prefix;
        }

        int prefix_idx;
        unsigned int clen;
        unsigned int cidx;
        prefix_tree_node_t* node = root;
        int child_idx;
        
        // the prefix must be under root
        for (prefix_idx = 0; prefix_idx < root->componentlen; prefix_idx++) {
                if (prefixbuf[prefix_idx] != root->icn_component[prefix_idx]) {
                        goto invalid_prefix;
                }
        }
        
        while (prefix_idx < prefixbuflen) {
		if (node->entity_id != 0) {
                        // every time finding a valid prefix, update token
			token_record = node->token;
		}
                if (node->children_num == 0) {
                        // like /edu/bit/lab101/news/ registering under /edu/bit/lab101/
                        goto tree_expand;
                }

                clen = 0;
                while (prefixbuf[prefix_idx + clen] != '/') ++clen;

                int found = 0;
                for (child_idx = 0; child_idx < node->children_num; child_idx++) {
                        
                        if (node->children[child_idx]->componentlen == clen) {
                                found = 1;
                                for (cidx = 0; cidx < clen; cidx++) {
                                        if (node->children[child_idx]->icn_component[cidx] != prefixbuf[prefix_idx + cidx]) {
                                                found = 0;
                                                break;
                                        }
                                }
                                if (found == 0) {
                                        continue;
                                }
                                else {
                                        node = node->children[child_idx];
					break;
                                }
                        }
                }
                if (found == 0) {
                        // like registering another prefix under /edu/bit/lab101/
                        goto tree_expand;
                }
                prefix_idx = prefix_idx + clen + 1;
        }
        if (node->entity_id != 0) {
                // prefix is exactly matched, so do EDIT or REJECT
                goto duplicate_name;
        }
        else {
                // if /edu/bit/lab101/news/2020/ has been registered,
                // then /edu/bit/lab101/news/ cannot be newly registered.
                goto not_obey_leaf_restraint;
        }
tree_expand:
        if (!checktoken_hash128(cmd->token, token_record, 32)) {
		// unauth
#ifdef PT_DEBUG
        printf("PT insert: prefix doesn't exists, and unauth cmd\n");
#endif
		pthread_rwlock_unlock(&pt_rwlock);
        	return -2;
	}
        while (prefix_idx < prefixbuflen) {                
                if (node->children_num == MAX_PTNODE_CHILDREN_NUM) {
                        goto invalid_prefix;
                }
                clen = 0;
                while (prefixbuf[prefix_idx + clen] != '/') ++clen;

                prefix_tree_node_t* newnode = prefix_tree_node_alloc(clen, prefixbuf + prefix_idx);
                node->children[node->children_num++] = newnode;
                
                node = node->children[node->children_num - 1];
                prefix_idx = prefix_idx + clen + 1;
        }
	node->expiretime = cmd->prefixexpiretime;
	node->entity_id = cmd->entity_id;
	memcpy(node->token, cmd->token, 16);
#ifdef PT_DEBUG
        printf("PT insert: prefix doesn't exist, insert succeed\n");
#endif
        pthread_rwlock_unlock(&pt_rwlock);
        return 0;

invalid_prefix:
#ifdef PT_DEBUG
        printf("PT insert: invalid prefix!\n");
#endif
        pthread_rwlock_unlock(&pt_rwlock);
        return -4;

duplicate_name:
        if (node->entity_id == cmd->entity_id && checktoken_hash128(cmd->token, node->token, 32)) {
                node->expiretime = cmd->prefixexpiretime;
                memcpy(node->token, cmd->token, 16);
#ifdef PT_DEBUG
        printf("PT insert: prefix exists, update\n");
#endif
		pthread_rwlock_unlock(&pt_rwlock);
                return -1;
        }
        else {
#ifdef PT_DEBUG
        printf("PT insert: prefix exists, unauth cmd\n");
#endif
                pthread_rwlock_unlock(&pt_rwlock);
                return -2;
        }

not_obey_leaf_restraint:
#ifdef PT_DEBUG
        printf("PT insert: more specific prefix exists, insert failed\n");
#endif
        pthread_rwlock_unlock(&pt_rwlock);
        return -3;
}

int 
prefix_tree_recursive_free(prefix_tree_node_t* root)
{
        if (root->children_num == 0) {
                if (prefix_tree_node_free(root) != 0)
                        return -1;
                else 
                        return 0;
        }
        int i;
        for (i = 0; i < root->children_num; i++) {
                if (prefix_tree_recursive_free(root->children[i]) != 0)
                        return -1;
        }
        return 0;
}

int
prefix_tree_node_delete(prefix_tree_node_t* root,
                        clientcommand_t* cmd)
{
        char *prefixbuf = cmd->prefixbuf;
        unsigned int prefixbuflen = cmd->prefixbuflen;
        pthread_rwlock_wrlock(&pt_rwlock);
        char *token_record = root->token;
        if (prefixbuflen <= root->componentlen 
                        || prefixbuf[0] != '/' 
                        || prefixbuf[prefixbuflen - 1] != '/') 
        {
                goto invalid_prefix;
        }

        int prefix_idx;
        unsigned int clen;
        unsigned int cidx;
        prefix_tree_node_t* node = root;
        int child_idx;

        for (prefix_idx = 0; prefix_idx < root->componentlen; prefix_idx++) {
                if (prefixbuf[prefix_idx] != root->icn_component[prefix_idx]) {
                        goto invalid_prefix;
                }
        }
        
        ptnode_stack_t* st = ptnode_stack_init();
        while (prefix_idx < prefixbuflen) {
                if (node->entity_id != 0) {
                        // every time finding a valid prefix, update token
			token_record = node->token;
		}
                if (node->children_num == 0) {
                        goto not_found;
                }

                clen = 0;
                while (prefixbuf[prefix_idx + clen] != '/') ++clen;

                int found = 0;
                for (child_idx = 0; child_idx < node->children_num; child_idx++) {
                        
                        if (node->children[child_idx]->componentlen == clen) {
                                found = 1;
                                for (cidx = 0; cidx < clen; cidx++) {
                                        if (node->children[child_idx]->icn_component[cidx] != prefixbuf[prefix_idx + cidx]) {
                                                found = 0;
                                                break;
                                        }
                                }
                                if (found == 0) {
                                        continue;
                                }
                                else {
                                        ptnode_stack_push(st, node, child_idx);
                                        node = node->children[child_idx];
                                        break;
                                }
                        }
                }
                if (found == 0) {
                        goto not_found;
                }
                prefix_idx = prefix_idx + clen + 1;
        }

        // if father prefix will be deleted, children prefix must be deleted!
        if (node->entity_id == cmd->entity_id && checktoken_hash128(cmd->token, token_record, 32))
                goto do_delete;
        else
                goto non_auth;
                
invalid_prefix:
        pthread_rwlock_unlock(&pt_rwlock);
        return -4;

do_delete:
        // delete prefix and all subtrees
        prefix_tree_recursive_free(node);
        // delete all single node above the prefix
        while (ptnode_stack_top(st) != NULL && 
                --ptnode_stack_top(st)->node->children_num == 0 &&
                ptnode_stack_top(st)->node->entity_id == 0 ) //!!debug
        {
                prefix_tree_node_free(ptnode_stack_pop(st)->node);
        }
        node = ptnode_stack_top(st)->node;
        child_idx = ptnode_stack_top(st)->child_idx;
        swap(&node->children[node->children_num], &node->children[child_idx]);
        pthread_rwlock_unlock(&pt_rwlock);
        return 0;

non_auth:
        pthread_rwlock_unlock(&pt_rwlock);
        return -2;

not_found:
        pthread_rwlock_unlock(&pt_rwlock);
        return -1;
}

int 
prefix_tree_recursive_free_withcallback(prefix_tree_node_t* root, 
                        void (*callback)(void*, void*), void* arg1, void*arg2)
{
        if (root->children_num == 0) {
                callback(arg1, arg2);
                if (prefix_tree_node_free(root) != 0)
                        return -1;
                else 
                        return 0;
        }
        // TBD: very very difficult!
        clientcommand_t precmd = *(clientcommand_t*)arg1;
        clientcommand_t curcmd = precmd;
        curcmd.prefixbuf = NULL;
        curcmd.valuelen = 0;
        curcmd.valuebuf = NULL;
        prefix_tree_node_t *child = NULL;
        int i, idx;
        for (i = 0; i < root->children_num; i++) {
                child = root->children[i];
                curcmd.prefixbuflen = precmd.prefixbuflen + child->componentlen + 1;
                curcmd.prefixbuf = malloc(curcmd.prefixbuflen);
                idx = precmd.prefixbuflen;
                memcpy(curcmd.prefixbuf, precmd.prefixbuf, precmd.prefixbuflen);
                memcpy(curcmd.prefixbuf + idx, child->icn_component, child->componentlen);
                idx += child->componentlen;
                *(curcmd.prefixbuf + idx) = '/';

                if (prefix_tree_recursive_free_withcallback(child, callback, &curcmd, arg2) != 0)
                        return -1;
                free(curcmd.prefixbuf);
        }
        callback(arg1, arg2);
        if (prefix_tree_node_free(root) != 0)
                return -1;
        else 
                return 0;
}

int
prefix_tree_node_delete_withcallback(prefix_tree_node_t* root,
                        clientcommand_t* cmd, void (*callback)(void*, void*), void* arg1, void* arg2)
{
        char *prefixbuf = cmd->prefixbuf;
        unsigned int prefixbuflen = cmd->prefixbuflen;
        pthread_rwlock_wrlock(&pt_rwlock);
        char *token_record = root->token;
        if (prefixbuflen <= root->componentlen 
                        || prefixbuf[0] != '/' 
                        || prefixbuf[prefixbuflen - 1] != '/') 
        {
                goto invalid_prefix;
        }

        int prefix_idx;
        unsigned int clen;
        unsigned int cidx;
        prefix_tree_node_t* node = root;
        int child_idx;

        for (prefix_idx = 0; prefix_idx < root->componentlen; prefix_idx++) {
                if (prefixbuf[prefix_idx] != root->icn_component[prefix_idx]) {
                        goto invalid_prefix;
                }
        }
        
        ptnode_stack_t* st = ptnode_stack_init();
        while (prefix_idx < prefixbuflen) {
                if (node->entity_id != 0) {
                        // every time finding a valid prefix, update token
			token_record = node->token;
		}
                if (node->children_num == 0) {
                        goto not_found;
                }

                clen = 0;
                while (prefixbuf[prefix_idx + clen] != '/') ++clen;

                int found = 0;
                for (child_idx = 0; child_idx < node->children_num; child_idx++) {
                        
                        if (node->children[child_idx]->componentlen == clen) {
                                found = 1;
                                for (cidx = 0; cidx < clen; cidx++) {
                                        if (node->children[child_idx]->icn_component[cidx] != prefixbuf[prefix_idx + cidx]) {
                                                found = 0;
                                                break;
                                        }
                                }
                                if (found == 0) {
                                        continue;
                                }
                                else {
                                        ptnode_stack_push(st, node, child_idx);
                                        node = node->children[child_idx];
                                        break;
                                }
                        }
                }
                if (found == 0) {
                        goto not_found;
                }
                prefix_idx = prefix_idx + clen + 1;
        }

        // if father prefix will be deleted, children prefix must be deleted!
        if (node->entity_id == cmd->entity_id && checktoken_hash128(cmd->token, token_record, 32))
                goto do_delete;
        else
                goto non_auth;
                
invalid_prefix:
#ifdef PT_DEBUG
        printf("PT delete: invalid prefix!\n");
#endif
        pthread_rwlock_unlock(&pt_rwlock);
        return -4;

do_delete:
        // delete prefix and all subtrees
        prefix_tree_recursive_free_withcallback(node, callback, arg1, arg2);
        // delete all single node above the prefix
        while (ptnode_stack_top(st) != NULL && 
                --ptnode_stack_top(st)->node->children_num == 0 &&
                ptnode_stack_top(st)->node->entity_id == 0 ) //!!debug
        {
                prefix_tree_node_free(ptnode_stack_pop(st)->node);
        }
        node = ptnode_stack_top(st)->node;
        child_idx = ptnode_stack_top(st)->child_idx;
        swap(&node->children[node->children_num], &node->children[child_idx]);
#ifdef PT_DEBUG
        printf("PT delete: prefix exists, delete succeed\n");
#endif
        pthread_rwlock_unlock(&pt_rwlock);
        return -1;

non_auth:
#ifdef PT_DEBUG
        printf("PT delete: prefix not found or unauth cmd\n");
#endif
        pthread_rwlock_unlock(&pt_rwlock);
        return -2;

not_found:
#ifdef PT_DEBUG
        printf("PT delete: prefix doesn't exist, delete faild\n");
#endif
        pthread_rwlock_unlock(&pt_rwlock);
        return 0;
}

int
prefix_tree_node_insert_fast(prefix_tree_node_t* root, 
                        clientcommand_t* cmd)
{
	//printf("[DBG1] cmd:%.*s\n", cmd->prefixbuflen, cmd->prefixbuf);
        // fast but not safe
        // won't check entityid and token, won't use lock, won't check prefix
        char *prefixbuf = cmd->prefixbuf;
        unsigned int prefixbuflen = cmd->prefixbuflen;
        int prefix_idx = root->componentlen;
        unsigned int clen;
        unsigned int cidx;
        prefix_tree_node_t* node = root;
        int child_idx;
        
        while (prefix_idx < prefixbuflen) {
                if (node->children_num == 0) {
                        // like /edu/bit/lab101/news/ registering under /edu/bit/lab101/
                        goto tree_expand;
                }

                clen = 0;
                while (prefixbuf[prefix_idx + clen] != '/') ++clen;

                int found = 0;
                for (child_idx = 0; child_idx < node->children_num; child_idx++) { 
                        if (node->children[child_idx]->componentlen == clen) {
                                found = 1;
                                for (cidx = 0; cidx < clen; cidx++) {
                                        if (node->children[child_idx]->icn_component[cidx] != prefixbuf[prefix_idx + cidx]) {
                                                found = 0;
                                                break;
                                        }
                                }
                                if (found == 0) {
                                        continue;
                                }
                                else {
                                        node = node->children[child_idx];
					break;
                                }
                        }
                }
                if (found == 0) {
                        // like registering another prefix under /edu/bit/lab101/
                        goto tree_expand;
                }
                prefix_idx = prefix_idx + clen + 1;
        }
        goto duplicate_name;
tree_expand:
        while (prefix_idx < prefixbuflen) {                
                if (node->children_num == MAX_PTNODE_CHILDREN_NUM) {
                        goto invalid_prefix;
                }
                clen = 0;
                while (prefixbuf[prefix_idx + clen] != '/') ++clen;

                prefix_tree_node_t* newnode = prefix_tree_node_alloc(clen, prefixbuf + prefix_idx);
                node->children[node->children_num++] = newnode;
                
                node = node->children[node->children_num - 1];
                prefix_idx = prefix_idx + clen + 1;
        }
	node->expiretime = cmd->prefixexpiretime;
	node->entity_id = cmd->entity_id;
	memcpy(node->token, cmd->token, 16);
        return 0;

invalid_prefix:
        return -2;

duplicate_name:    
        node->expiretime = cmd->prefixexpiretime;
        memcpy(node->token, cmd->token, 16);
        return 0;

not_obey_leaf_restraint:
	//printf("[DBG2] cmd:%.*s\n", cmd->prefixbuflen, cmd->prefixbuf);
        return -1;
}

int
prefix_tree_node_delete_fast(prefix_tree_node_t* root,
                        clientcommand_t* cmd)
{
	//printf("[DBG3] cmd:%.*s\n", cmd->prefixbuflen, cmd->prefixbuf);
        // fast but not safe
        // won't check entityid and token, won't use lock, won't check prefix
        char *prefixbuf = cmd->prefixbuf;
        unsigned int prefixbuflen = cmd->prefixbuflen;
        int prefix_idx = root->componentlen;
        unsigned int clen;
        unsigned int cidx;
        prefix_tree_node_t* node = root;
        int child_idx;
    
        ptnode_stack_t* st = ptnode_stack_init();
        while (prefix_idx < prefixbuflen) {
                if (node->children_num == 0) {
                        goto not_found;
                }

                clen = 0;
                while (prefixbuf[prefix_idx + clen] != '/') ++clen;

                int found = 0;
                for (child_idx = 0; child_idx < node->children_num; child_idx++) {
                        
                        if (node->children[child_idx]->componentlen == clen) {
                                found = 1;
                                for (cidx = 0; cidx < clen; cidx++) {
                                        if (node->children[child_idx]->icn_component[cidx] != prefixbuf[prefix_idx + cidx]) {
                                                found = 0;
                                                break;
                                        }
                                }
                                if (found == 0) {
                                        continue;
                                }
                                else {
                                        ptnode_stack_push(st, node, child_idx);
                                        node = node->children[child_idx];
                                        break;
                                }
                        }
                }
                if (found == 0) {
                        goto not_found;
                }
                prefix_idx = prefix_idx + clen + 1;
        }

        // if father prefix will be deleted, children prefix must be deleted!
        goto do_delete;
                
invalid_prefix:
        return -2;

do_delete:
        // delete prefix and all subtrees
        prefix_tree_recursive_free(node);
        // delete all single node above the prefix
        while (ptnode_stack_top(st) != NULL && 
                --ptnode_stack_top(st)->node->children_num == 0 &&
                ptnode_stack_top(st)->node->entity_id == 0 ) //!!debug
        {
                prefix_tree_node_free(ptnode_stack_pop(st)->node);
        }
        node = ptnode_stack_top(st)->node;
        child_idx = ptnode_stack_top(st)->child_idx;
        swap(&node->children[node->children_num], &node->children[child_idx]);
        return 0;
not_found:
	//printf("[DBG4] cmd:%.*s\n", cmd->prefixbuflen, cmd->prefixbuf);
        return -1;
}

int 
prefix_tree_destroy(prefix_tree_node_t* root)
{
        pthread_rwlock_wrlock(&pt_rwlock);
        prefix_tree_recursive_free(root);
        pthread_rwlock_unlock(&pt_rwlock);
        pthread_rwlock_destroy(&pt_rwlock);
        return 0;
}

ptnode_stack_t*
ptnode_stack_init()
{
        ptnode_stack_t* st = (ptnode_stack_t*)malloc(sizeof(ptnode_stack_t));
        st->top = 0;
        return st;
}

int
ptnode_stack_push(ptnode_stack_t* st, prefix_tree_node_t* node, unsigned int child_idx)
{
        if (st->top == MAX_PTNODE_CHILDREN_NUM) {
                return -1;
        }
        st->item[st->top].node = node;
        st->item[st->top].child_idx = child_idx;

        ++st->top;
        return 0;
}

ptnode_item_t*
ptnode_stack_pop(ptnode_stack_t* st)
{
        if (st->top == 0) {
                return NULL;
        }
        return &st->item[--st->top];
}

ptnode_item_t*
ptnode_stack_top(ptnode_stack_t* st)
{
        if (st->top == 0) {
                return NULL;
        }
        return &st->item[st->top - 1];
}

void 
prefix_tree_print(prefix_tree_node_t* root)
{
        pthread_rwlock_wrlock(&pt_rwlock);
        ptnode_queue_t* qu = ptnode_queue_init();
        int front = -1, rear = 0, last = 0, i;
        prefix_tree_node_t* node = root;
        ptnode_queue_push(qu, node);
        printf("\n====== start ======\n");
        while (!ptnode_queue_empty(qu)) {
                node = ptnode_queue_pop(qu);
                ++front;
                printf("%.*s\t", node->componentlen, node->icn_component);
                for (i = 0; i < node->children_num; i++) {
                        ptnode_queue_push(qu, node->children[i]);
                        ++rear;
                }
                if (front == last) {
                        printf("\n");
                        last = rear;
                }
        }
        printf("======= end =======\n");
        pthread_rwlock_unlock(&pt_rwlock);
}

void 
prefix_tree_visit_withcallback(prefix_tree_node_t* root, 
                        void (*callback)(void*, void*, void*, void*), 
                        void* arg)
{
        // 性能无法保证
        pthread_rwlock_rdlock(&pt_rwlock);
        ptnode_queue_t* qu = ptnode_queue_init();
        char complete_prefix[256];
        char *reverse_ptr = complete_prefix + 256;
        int complete_prefixlen = 0;
        int front = -1, rear = 0, last = 0, i;
        prefix_tree_node_t* node = root;
        prefix_tree_node_t* reverse_node = NULL;
        ptnode_queue_push(qu, node);
        while (!ptnode_queue_empty(qu)) {
                node = ptnode_queue_pop(qu);
                if (node->entity_id != 0 && node != root) { // root 节点不需要重建
                        reverse_node = node;
                        reverse_ptr = complete_prefix + 256;
                        complete_prefixlen = 0;
                        while (reverse_node != root) {
                                reverse_ptr -= (reverse_node->componentlen + 1);
                                memcpy(reverse_ptr, reverse_node->icn_component, reverse_node->componentlen);
                                *(reverse_ptr + reverse_node->componentlen) = '/';
                                complete_prefixlen += (reverse_node->componentlen + 1);
                                reverse_node = reverse_node->parent;
                        }
                        reverse_ptr -= reverse_node->componentlen; // root: /edu/bit/
                        memcpy(reverse_ptr, reverse_node->icn_component, reverse_node->componentlen);
                        complete_prefixlen += reverse_node->componentlen;
			//printf("[DBG] node childnum = %d, qu(%d,%d)\n", node->children_num, qu->front, qu->rear);
			//printf("[DBG] len: %d, prefix: %.*s\n", complete_prefixlen, complete_prefixlen, reverse_ptr);
                        callback(node, reverse_ptr, &complete_prefixlen, arg);
                }
                ++front;
                for (i = 0; i < node->children_num; i++) {
                        node->children[i]->parent = node; // for complete prefix
                        ptnode_queue_push(qu, node->children[i]);
                        ++rear;
                }
                if (front == last) {
                        last = rear;
                }
        }
        pthread_rwlock_unlock(&pt_rwlock);
}

ptnode_queue_t*
ptnode_queue_init()
{
        ptnode_queue_t* qu = (ptnode_queue_t*)malloc(sizeof(ptnode_queue_t));
        qu->front = 0;
        qu->rear = 0;
        return qu;
}

int
ptnode_queue_push(ptnode_queue_t* qu, prefix_tree_node_t* node)
{
        if ((qu->rear + 1) % MAX_PTNODE_WIDTH == qu->front) {
                return -1;
        }
        qu->item[qu->rear++] = node;
        qu->rear %= MAX_PTNODE_WIDTH;
        return 0;
}

prefix_tree_node_t*
ptnode_queue_pop(ptnode_queue_t* qu)
{
        if (ptnode_queue_empty(qu)) {
                return NULL;
        }
        prefix_tree_node_t* node = qu->item[qu->front++];
        qu->front %= MAX_PTNODE_WIDTH;
        return node;
}

prefix_tree_node_t*
ptnode_queue_front(ptnode_queue_t* qu)
{
        if (ptnode_queue_empty(qu)) {
                return NULL;
        }
        return qu->item[qu->front];
}
