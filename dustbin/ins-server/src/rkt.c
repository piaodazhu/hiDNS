#include "rkt.h"

robinkarp_table_t rkt;

int compute_rkv(const char* prefix, int prefixlen, int mul, int mod)
{
	int num = 0, i = 0;
	for (i = 0; i < prefixlen; i++) {
		num *= mul;
		num += prefix[i];
		num %= mod;
	}
	return num;
}


void rkt_init()
{
	rkt.compute_mul = 97;
	rkt.default_mod = 1e7+7;
	rkt.table_len = 0;
	int idx = 0;
	for (idx = 0; idx < ROBIN_KARP_TABLE_SIZE; idx++) {
		rkt.table[idx].path = NULL;
		rkt.table[idx].path_num = 0;
		rkt.table[idx].compute_mod = rkt.default_mod;
	}
}

int rkt_add_path(const char* prefix, int prefixlen, 
	void* sockbuf, int socklen, void (*process_module) (void *sargs, char* pktbuf, int pktlen, const struct prefix_path *path))
{
	if (ROBIN_KARP_TABLE_SIZE < prefixlen) {
		return -1;
	}
	prefix_path_t* ppath = (prefix_path_t*) malloc (sizeof(prefix_path_t));
	
	ppath->pathlen = prefixlen;
	ppath->pathbuf = malloc(prefixlen);
	memcpy(ppath->pathbuf, prefix, prefixlen);
	memcpy(&ppath->dst, sockbuf, socklen);
	ppath->process_module = process_module;
	ppath->isfinal = 1;
	ppath->rkv = compute_rkv(prefix, prefixlen, rkt.compute_mul, rkt.table[prefixlen - 1].compute_mod);
	
	ppath->next = rkt.table[prefixlen - 1].path;
	rkt.table[prefixlen - 1].path = ppath;
	rkt.table[prefixlen - 1].path_num++;

	// keep table_len = maxprefielen
	rkt.table_len = rkt.table_len < prefixlen ? prefixlen : rkt.table_len;
	return 0;
}

int rkt_finish_build()
{
	int i = 0;
	int tmpbufsize;
	int tmpbufidx;
	int* tmpbuf = NULL;
	prefix_path_t* ppath = NULL;
	
	for (i = 0; i < rkt.table_len; i++) {
		if (rkt.table[i].path_num < 2) {
			continue;
		}

		tmpbufsize = rkt.table[i].path_num;
		tmpbuf = (int*) malloc (tmpbufsize * sizeof(int));

		for (tmpbufidx = 0, ppath = rkt.table[i].path; ppath != NULL; ppath = ppath->next) {
			tmpbuf[tmpbufidx++] = ppath->rkv;
		}

		// insert sort argorithm
		int j, k, n;
		int check_unique_times = 0;
check_unique:
		if (check_unique_times > 10) {
			printf("same prefix to different modules has not been supported yet! check your configuration.\n");
			exit(1);
		}


		for (j = 1; j < tmpbufsize; j++) {
			n = tmpbuf[j];
			for (k = j - 1; k >= 0; k--) {
				if (tmpbuf[k] > n) {
					tmpbuf[k + 1] = tmpbuf[k];
				}
				else if (tmpbuf[k] == n) {
					// ! found same rkv
					rkt.table[i].compute_mod += 10;
					for (tmpbufidx = 0, ppath = rkt.table[i].path; ppath != NULL; ppath = ppath->next) {
						ppath->rkv = compute_rkv(ppath->pathbuf, ppath->pathlen, 
									rkt.compute_mul, rkt.table[i].compute_mod);
						tmpbuf[tmpbufidx++] = ppath->rkv;
					}
					check_unique_times++;
					goto check_unique;
				} else {
					break;
				}
			}
			tmpbuf[k + 1] = n;
		}
		free(tmpbuf);
	}

	// find and set most common compute_mod
	int flagbuf[ROBIN_KARP_TABLE_SIZE];
	int j, k, m, n, max = 0;
	for (j = 0; j < rkt.table_len; j++) {
		flagbuf[j] = (rkt.table[j].path_num != 0);
	}
	for (j = 0; j < rkt.table_len; j++) {
		if (flagbuf[j] == 0) {
			continue;
		}
		m = rkt.table[j].compute_mod;
		n = 0;
		for (k = 0; k < rkt.table_len; k++) {
			if (flagbuf[k] != 0 && m == rkt.table[k].compute_mod) {
				++n;
				flagbuf[k] = 0;
			}
		}
		if (n > max) {
			rkt.default_mod = m;
			max = n;
		}
	}

	// set isfinal flag by scan all prefix
	// example: /edu/bit/lab101/ will make /edu/bit/ set isfinal to 0
	int rkv, mul = rkt.compute_mul;
	for (j = rkt.table_len - 1; j >= 0; j--) {
		for (ppath = rkt.table[j].path; ppath != NULL; ppath = ppath->next) {
			char* prefix = ppath->pathbuf;
			int len = ppath->pathlen;
			for (k = 0; k < len - 2; ++k) {
				if (prefix[k] == '/' && rkt.table[k].path_num > 0) {
					rkv = compute_rkv(prefix, k + 1, mul, rkt.table[k].compute_mod);
					// set same rkv path to 0
					prefix_path_t* subppath = NULL;
					for (subppath = rkt.table[k].path; subppath != NULL; subppath = subppath->next) {
						if (subppath->rkv == rkv) {
							subppath->isfinal = 0;
						}
					}
				}
			}
		}
	}

	return 0;
}


int rkt_route(void *sargs, char* name, int nlen, char* pktbuf, int pktlen)
{
	// TBD: extract name from packet first, here we do this simply
	int maxprefixlen = nlen < rkt.table_len ? nlen : rkt.table_len;

	prefix_path_t* matched_path = NULL;
	int i, rkv = 0, tmprkv;
	int mod = rkt.default_mod, mul = rkt.compute_mul;
	for (i = 0; i < maxprefixlen; i++) {

		rkv *= mul;
		rkv += name[i];
		rkv %= mod;

		if (name[i] == '/' && rkt.table[i].path_num != 0) {
			if (rkt.table[i].compute_mod != mod) {
			// unfortunately, we have to compute rkv again
				tmprkv = compute_rkv(name, i + 1, mul, rkt.table[i].compute_mod);
			} else {
			// rkv can do matching
				tmprkv = rkv;
			}
			prefix_path_t* ppath = rkt.table[i].path;
			for (; ppath != NULL; ppath = ppath->next) {
				if (tmprkv == ppath->rkv) {
					matched_path = ppath;
					break;
				}
			}
		}
		// is find a matched path and it is longest prefix in all rules, break.
		if (matched_path != NULL && matched_path->isfinal == 1) {
			break;
		}
	}

	matched_path->process_module(sargs, pktbuf, pktlen, matched_path);
	return 0;
}