# libins-resolv

## what's This?

`libins-resolv` is an INS resolver implementation library. It's an important part of INS (ICN Name System). It allows user get RR (Resource Record) by specifiying an ICN-style name (such as /edu/bit/lab101/news/2021/xx.yy.zz). 

Not only names of ICN Name System can be resolved, but also does named mapped from current Internet Domain Name System (such as /com/jd/www/somesubdirs/ and /com/baidu/xx/yy/zz).

More details is [here]().

## How to Build?

Before build `libins-resolv`, make sure `redis-server` and `hiredis` has been installed first. Then:

```sh
cd lib
sudo make install
```

If no error occurs, you can add `#include <ins-resolv.h>` in C programs, and add arguments `-lins-resolv` when compiling. 

To test `libins-resolv`:

```sh
cd {redisdir}/src/
./redis-server
cd {ins-resolvdir}/test/
make
./ins-client {ins-serverIP} {/target/name/to/be/resolved} {mincomponents} {maxcomponents}
```

## How To Use?

`libins-resolv` provide these APIs:

```c
# include <ins-resolv.c>

// name and nameserver must be C string ending with 0
struct hostent*
ins_gethostbyname(const char* name, const char* nameserver, 
			int mincomponentcount, int maxcomponentcount);

// prefix and nameserver must be C string ending with 0
struct hostent*
ins_gethostbyprefix(const char* prefix, const char* nameserver);

//-----------------
// name and nameserver must be C string ending with 0
in_addr_t*
ins_getaddrbyname(const char* name, const char* nameserver, 
			int mincomponentcount, int maxcomponentcount);

// name and nameserver must be C string ending with 0
ins_ans_entry*
ins_getnsbyname(const char* name, const char* nameserver, 
			int mincomponentcount, int maxcomponentcount);

// name and nameserver must be C string ending with 0
ins_ans_entry*
ins_gettxtbyname(const char* name, const char* nameserver, 
			int mincomponentcount, int maxcomponentcount);

// name and nameserver must be C string ending with 0
ins_ans_entry*
ins_getsoabyname(const char* name, const char* nameserver, 
			int mincomponentcount, int maxcomponentcount);


in_addr_t*
ins_getaddrbyname2(const char* name, int nlen, const struct sockaddr_in *nameserver, 
			int mincomponentcount, int maxcomponentcount);


ins_ans_entry*
ins_getnsbyname2(const char* name, int nlen, const struct sockaddr_in *nameserver,
			int mincomponentcount, int maxcomponentcount);


ins_ans_entry*
ins_gettxtbyname2(const char* name, int nlen, const struct sockaddr_in *nameserver,
			int mincomponentcount, int maxcomponentcount);


ins_ans_entry*
ins_getsoabyname2(const char* name, int nlen, const struct sockaddr_in *nameserver,
			int mincomponentcount, int maxcomponentcount);

//-----------------

void
ins_free_hostent(struct hostent*);

void
ins_free_aentry(ins_ans_entry*);

void
ins_free_addrlist(in_addr_t*);


// input query packet and output answer packet from nameserver
int
ins_resolv(const struct sockaddr_in *nameserver,
	const ins_qry_buf *qbuf, int qlen, ins_ans_buf *abuf, int *alen);

```

Some structures are defined in `<ins_msgformat.h>`. More details is [here]().

```c
typedef struct {
	unsigned	id: 16;
#if __BYTE_ORDER == __BIG_ENDIAN
			/* fields in third byte */
	unsigned	hoplimit :4;	/*%< hoplimit of query forwarding */
	unsigned	reserved: 2;	/*%< reserved */
	unsigned	rd: 1;		/*%< recursion desired */
	unsigned	aa :1;		/*%< authoritive answer */
			/* fields in fourth byte */
	unsigned	maxcn :4;	/*%< maximum components number */
	unsigned	mincn :4;	/*%< minimum components number */
#endif
#if __BYTE_ORDER == __LITTLE_ENDIAN || __BYTE_ORDER == __PDP_ENDIAN
			/* fields in third byte */	
	unsigned	rd :1;		/*%< recursion desired */
	unsigned	aa :1;		/*%< authoritive answer */
	unsigned	reserved :2;	/*%< reserved */
	unsigned	hoplimit :4;	/*%< hoplimit of query forwarding */

			/* fields in fourth byte */
	unsigned	mincn :4;	/*%< minimum components number */
	unsigned	maxcn :4;	/*%< maximum components number */

#endif
			/* remaining bytes */
	unsigned	qtype	:8;	/*%< required type of query */
	unsigned	qnlen	:8;	/*%< name length of query */
} INS_QUERY_HEADER;


typedef struct {
	unsigned	id: 16;
#if __BYTE_ORDER == __BIG_ENDIAN
			/* fields in third byte */
	unsigned	rcode: 4;	/*%< response code */
	unsigned	reserved: 2;	/*%< reserved */
	unsigned	ad: 1;		/*%< authoritic data */
	unsigned	ra :1;		/*%< recursion available */
			/* fields in fourth byte */
	unsigned	exacn :4;	/*%< exact components number */
	unsigned	ancount :4;	/*%< number of answer entries */
#endif
#if __BYTE_ORDER == __LITTLE_ENDIAN || __BYTE_ORDER == __PDP_ENDIAN
			/* fields in third byte */	
	unsigned	ra :1;		/*%< recursion available */
	unsigned	ad :1;		/*%< authoritic data */
	unsigned	reserved :2;	/*%< reserved */
	unsigned	rcode: 4;	/*%< response code */
			/* fields in fourth byte */
	unsigned	ancount :4;	/*%< number of answer entries */
	unsigned	exacn :4;	/*%< exact components number */
#endif
			/* remaining bytes */
	unsigned	exaplen	:8;	/*%< exact prefix length */
} INS_ANSWER_HEADER;

typedef struct {
	unsigned int	ttl;
	unsigned char	type;
	unsigned short	length;
	unsigned char	*value;
} ins_ans_entry;

typedef union {
	INS_QUERY_HEADER	header;
	unsigned char		buf[INS_MAXPKTSIZE];
} ins_qry_buf;

typedef union {
	INS_ANSWER_HEADER	header;
	unsigned char		buf[INS_MAXPKTSIZE];
} ins_ans_buf;

```
