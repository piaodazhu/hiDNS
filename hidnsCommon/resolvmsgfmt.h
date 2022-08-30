#ifndef RESOLV_MSG_FORMAT_H
#define RESOLV_MSG_FORMAT_H
#include <endian.h>
#include <arpa/nameser.h>

#define INS_UDPMAXSIZE	1472
#define INS_BUFMAXSIZE	2048
#define INS_PFXMAXSIZE	256
#define INS_QHEADERSIZE	9
#define INS_AHEADERSIZE	10
#define INS_ENTRYFIXLEN	8

#define INS_T_A		T_A
#define INS_T_NS	T_NS
#define INS_T_CNAME	T_CNAME
#define INS_T_SOA	T_SOA
#define INS_T_TXT	T_TXT
#define INS_T_CERT	T_CERT
#define INS_T_RRSIG	T_RRSIG
#define INS_T_HSIG	222
#define INS_T_HADMIN	223

#define INS_RCODE_OK			0x0	/*%< succeed getting resource record */

#define INS_RCODE_RECORDNOTFOUND	0x1	/*%< resource record not found */
#define INS_RCODE_EXCEEDHOPLIMIT	0x2	/*%< can't resolve by forwarding */
#define INS_RCODE_CANT_PARSE_ANS	0x3	/*%< error occurs when parse DNS answer */

#define INS_RCODE_CACHE_NORECORD	0x4	/*%< error occurs when empty answer is cached */
#define INS_RCODE_SERVER_TOOBUSY	0x5	/*%< error occurs when server is busy */

#define INS_RCODE_INVALID_RRTYPE	0xA	/*%< invalid resource record type */
#define INS_RCODE_INVALID_PACKET	0xB	/*%< invalid query packet format */
#define INS_RCODE_INVALID_PREFIX	0xD	/*%< invalid prefix format in query */
#define INS_RCODE_INVALID_CCOUNT	0xC	/*%< invalid component count in query */
#define INS_RCODE_INVALID_DNSARG	0xE	/*%< invalid component count for DNS */
#define INS_RCODE_INVALID_INSARG	0xF	/*%< invalid component count for INS */




typedef struct {
	unsigned	id: 32;
#if __BYTE_ORDER == __BIG_ENDIAN
			/* fields in fifth byte */	
	unsigned	z  :1;		/*%< must be zero */
	unsigned	od :1;		/*%< over dtls*/
	unsigned	ad :1;		/*%< authentic data */
	unsigned	cd :1;		/*%< checking disabled */
	unsigned	ra :1;		/*%< recursion available */
	unsigned	rd :1;		/*%< recursion desired */
	unsigned	tc :1;		/*%< truncation */
	unsigned	aa :1;		/*%< authoritative answer */
			/* fields in sixth byte */
	unsigned	hoplimit :4;	/*%< hoplimit of query forwarding */
	unsigned	reserved :4;	/*%< reserved */
			/* fields in seventh byte */
	unsigned	maxcn :4;	/*%< maximum components number */
	unsigned	mincn :4;	/*%< minimum components number */

#endif
#if __BYTE_ORDER == __LITTLE_ENDIAN || __BYTE_ORDER == __PDP_ENDIAN
			/* fields in fifth byte */
	unsigned	aa :1;		/*%< authoritative answer */
	unsigned	tc :1;		/*%< truncation */
	unsigned	rd :1;		/*%< recursion desired */
	unsigned	ra :1;		/*%< recursion available */
	unsigned	cd :1;		/*%< checking disabled */
	unsigned	ad :1;		/*%< authentic data */	
	unsigned	od :1;		/*%< over dtls*/
	unsigned	z  :1;		/*%< must be zero */
			/* fields in sixth byte */
	unsigned	reserved :4;	/*%< reserved */
	unsigned	hoplimit :4;	/*%< hoplimit of query forwarding */
			/* fields in seventh byte */
	unsigned	mincn :4;	/*%< minimum components number */
	unsigned	maxcn :4;	/*%< maximum components number */

#endif
			/* remaining bytes */
	unsigned	qtype	:8;	/*%< required type of query */
	unsigned	qnlen	:8;	/*%< name length of query */
} INS_QUERY_HEADER;


typedef struct {
	unsigned	id: 32;
#if __BYTE_ORDER == __BIG_ENDIAN
			/* fields in fifth byte */	
	unsigned	z  :1;		/*%< must be zero */
	unsigned	od :1;		/*%< over dtls*/
	unsigned	ad :1;		/*%< authentic data */
	unsigned	cd :1;		/*%< checking disabled */
	unsigned	ra :1;		/*%< recursion available  */
	unsigned	rd :1;		/*%< recursion desired */
	unsigned	tc :1;		/*%< truncation */
	unsigned	aa :1;		/*%< authoritative answer */
			/* fields in sixth byte */
	unsigned	hoplimit :4;	/*%< hoplimit of query forwarding */
	unsigned	reserved :4;	/*%< reserved */
			/* fields in seventh byte */
	unsigned	exacn :4;	/*%< exact components number */
	unsigned	rcode: 4;	/*%< response code */

#endif
#if __BYTE_ORDER == __LITTLE_ENDIAN || __BYTE_ORDER == __PDP_ENDIAN
			/* fields in fifth byte */
	unsigned	aa :1;		/*%< authoritative answer */
	unsigned	tc :1;		/*%< truncation */
	unsigned	rd :1;		/*%< recursion desired */
	unsigned	ra :1;		/*%< recursion available  */
	unsigned	cd :1;		/*%< checking disabled */
	unsigned	ad :1;		/*%< authentic data */	
	unsigned	od :1;		/*%< over dtls*/
	unsigned	z  :1;		/*%< must be zero */
			/* fields in sixth byte */
	unsigned	reserved :4;	/*%< reserved */
	unsigned	hoplimit :4;	/*%< hoplimit of query forwarding */
			/* fields in seventh byte */
	unsigned	rcode: 4;	/*%< response code */
	unsigned	exacn :4;	/*%< exact components number */
#endif
			/* remaining bytes */
	unsigned	exaplen	:8;	/*%< exact prefix length */
	unsigned	qtype	:8;	/*%< required type of query */
	unsigned	ancount :8;	/*%< number of answer entries */
} INS_ANSWER_HEADER;

typedef struct {
	unsigned int	ttl;
	unsigned char	type;
	unsigned char	reserved;
	unsigned short	length;
	unsigned char	*value;
} ins_ans_entry;

typedef union {
	INS_QUERY_HEADER	header;
	unsigned char		buf[INS_UDPMAXSIZE];
} ins_qry_buf;

typedef union {
	INS_ANSWER_HEADER	header;
	unsigned char		buf[INS_UDPMAXSIZE];
} ins_ans_buf;

int 
ins_init_query_buf(ins_qry_buf* ins_qbuf, unsigned char* bound, const char* name, int nlen);

int
get_ins_ans_entry(unsigned char* ptr, unsigned char* bound, ins_ans_entry* entry);

int
set_ins_ans_entry(unsigned char* ptr, unsigned char* bound, ins_ans_entry* entry);

unsigned int
get_ins_ans_ttl(const ins_ans_buf* ins_abuf);

unsigned int
get_ins_entry_len(const unsigned char* entrybuf);


#endif