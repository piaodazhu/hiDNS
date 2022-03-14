#ifndef INSPREFIX_H
#define INSPREFIX_H

#define CHECKPREFIX_INVALID_SYMBOL      -1
#define CHECKPREFIX_TOOLONG_PREFIX      -2
#define CHECKPREFIX_TOOLONG_COMPONENT   -3
#define CHECKPREFIX_TOOMANY_COMPONENT   -4
// #define CHECKPREFIX_EMPTY_COMPONENT     -5

int
insprefix_check_withmaxcn(unsigned char* name, int nlen, int maxcn, int* exacn, int* exaplen);

int
insprefix_cn2plen(unsigned char* name, int nlen, int componentsnum);

int
insprefix_prefix2domainname(const char* prefix, int plen, char* domainname, int dlen);

int
insprefix_prefix2domainname_nocheck(const char* prefix, int plen, char* domainname, int dlen);

#endif