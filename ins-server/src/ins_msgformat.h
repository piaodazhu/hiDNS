#ifndef INS_MSG_FORMAT_H
#define INS_MSG_FORMAT_H
#include <endian.h>
#include <arpa/nameser.h>

#define INS_MAXPKTSIZE	512
#define INS_QHEADERSIZE	6
#define INS_AHEADERSIZE	5

#define INS_T_A		T_A
#define INS_T_NS	T_NS
#define INS_T_CNAME	T_CNAME
#define INS_T_SOA	T_SOA
#define INS_T_TXT	T_TXT

#define INS_RCODE_OK			0x0	/*%< succeed getting resource record */

#define INS_RCODE_RECORDNOTFOUND	0x1	/*%< resource record not found */
#define INS_RCODE_EXCEEDHOPLIMIT	0x2	/*%< can't resolve by forwarding */
#define INS_RCODE_CANT_PARSE_ANS	0x3	/*%< error occurs when parse DNS answer */

#define INS_RCODE_CACHE_NORECORD	0x4	/*%< error occurs when empty answer is cached */

#define INS_RCODE_INVALID_PACKET	0xB	/*%< invalid query packet format */
#define INS_RCODE_INVALID_PREFIX	0xD	/*%< invalid prefix format in query */
#define INS_RCODE_INVALID_CCOUNT	0xC	/*%< invalid component count in query */
#define INS_RCODE_INVALID_DNSARG	0xE	/*%< invalid component count for DNS */
#define INS_RCODE_INVALID_INSARG	0xF	/*%< invalid component count for INS */




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

int 
ins_init_query_buf(ins_qry_buf* ins_qbuf, unsigned char* bound, const char* name, int nlen);

int
get_ins_ans_entry(unsigned char* ptr, unsigned char* bound, ins_ans_entry* entry);

int
set_ins_ans_entry(unsigned char* ptr, unsigned char* bound, ins_ans_entry* entry);

unsigned int
get_ins_ans_ttl(const ins_ans_buf* ins_abuf);

#endif