#include "updatezone.h"

const char* idns_nsupdate_class[4] = {"", "A", "TXT", "CNAME"};
pthread_mutex_t rrup_mxlock;

void idns_rrup_lock_init()
{
        pthread_mutex_init(&rrup_mxlock, NULL);
}

void idns_rrup_lock_destroy()
{
        pthread_mutex_destroy(&rrup_mxlock);
}

idns_updateinfo_t* idns_rrup_updateinfo_alloc() 
{
        idns_updateinfo_t* uinfo = (idns_updateinfo_t*) malloc (sizeof(idns_updateinfo_t));
        uinfo->opcode = IDNS_OPCODE_NON;
        uinfo->serverlen = strlen(RESPONSIBLE_SERVER);
        uinfo->server = malloc(uinfo->serverlen);
        memcpy(uinfo->server, RESPONSIBLE_SERVER, uinfo->serverlen);
        uinfo->RRdomainnamelen = 0;
        uinfo->RRdomainname = malloc(256);
        uinfo->RRttl = 86400;
        uinfo->RRclass = IDNS_RRCLASS_NON;
        uinfo->RRvaluelen = 0;
        uinfo->RRvalue = malloc(256);
        return uinfo;
}

void idns_rrup_updateinfo_free(idns_updateinfo_t* uinfo) 
{
        free(uinfo->server);
        free(uinfo->RRdomainname);
        free(uinfo->RRvalue);
        free(uinfo);
}

int idns_rrup_update_rr(idns_updateinfo_t* uinfo)
{
        char fbuf[2048];
        char *fptr = fbuf;
        unsigned int fbuf_len = 0;

        fptr += sprintf(fptr, "server %.*s\n", uinfo->serverlen, uinfo->server);
        switch (uinfo->opcode)
        {
        case IDNS_OPCODE_ADD:
                fptr += sprintf(fptr, "update add %.*s %d %.*s %.*s\n",
                                        uinfo->RRdomainnamelen, uinfo->RRdomainname,
                                        uinfo->RRttl,
                                        (int)strlen(idns_nsupdate_class[uinfo->RRclass]), 
                                        idns_nsupdate_class[uinfo->RRclass],
                                        uinfo->RRvaluelen, uinfo->RRvalue);
                break;
        
        case IDNS_OPCODE_DEL:
                fptr += sprintf(fptr, "update delete %.*s %.*s",
                                uinfo->RRdomainnamelen, uinfo->RRdomainname,
                                (int)strlen(idns_nsupdate_class[uinfo->RRclass]), 
                                idns_nsupdate_class[uinfo->RRclass]);
                if (uinfo->RRvaluelen == 0)
                        fptr += sprintf(fptr, "\n");
                else
                        fptr += sprintf(fptr, " %.*s\n", uinfo->RRvaluelen, uinfo->RRvalue);
                break;
        
        case IDNS_OPCODE_EDIT:
                fptr += sprintf(fptr, "update delete %.*s %.*s",
                                uinfo->RRdomainnamelen, uinfo->RRdomainname,
                                (int)strlen(idns_nsupdate_class[uinfo->RRclass]), 
                                idns_nsupdate_class[uinfo->RRclass]);
                if (uinfo->RRvaluelen == 0)
                        fptr += sprintf(fptr, "\n");
                else
                        fptr += sprintf(fptr, " %.*s\n", uinfo->RRvaluelen, uinfo->RRvalue);
                
                fptr += sprintf(fptr, "update add %.*s %d %.*s %.*s\n",
                                        uinfo->RRdomainnamelen, uinfo->RRdomainname,
                                        uinfo->RRttl,
                                        (int)strlen(idns_nsupdate_class[uinfo->RRclass]), 
                                        idns_nsupdate_class[uinfo->RRclass],
                                        uinfo->RRvaluelen, uinfo->RRvalue);
                
                break;
        default:
                break;
        }
        
        fptr += sprintf(fptr, "send\n");
        fbuf_len = fptr - fbuf;

        pthread_mutex_lock(&rrup_mxlock);

        char *filename = "nsu.ida";
        FILE *fp = fopen(filename, "w");
        fwrite(fbuf, fbuf_len, 1, fp);
        fclose(fp);

        int childpid;
        if (fork() == 0){  
                //child process  
                if (execlp("nsupdate", "nsupdate", filename, NULL) < 0 ) {  
                        perror("error on exec nsupdate");  
                        exit(0);  
                }  
        }else{  
                //parent process  
                wait(&childpid);  
                printf("nsupdate done, childpid = %d\n", childpid);  
        }
#ifndef KEEP_NSU
        remove(filename);
#endif
        pthread_mutex_unlock(&rrup_mxlock);
        return 0;
}

int idns_rrup_flush()
{
        int childpid;
        pthread_mutex_lock(&rrup_mxlock);
        if (fork() == 0){  
                //child process  
                if (execlp("rndc", "rndc", "freeze", RESPONSIBLE_ZONE, NULL) < 0 ) {  
                        perror("error on exec rndc freeze");  
                        exit(0);  
                }  
        }else{  
                //parent process  
                wait(&childpid);  
                printf("rndc freeze done, childpid = %d\n", childpid);  
        }

        if (fork() == 0){  
                //child process  
                if (execlp("rndc", "rndc", "reload", RESPONSIBLE_ZONE, NULL) < 0 ) {  
                        perror("error on exec rndc reload");  
                        exit(0);  
                }  
        }else{  
                //parent process  
                wait(&childpid);  
                printf("rndc reload done, childpid = %d\n", childpid);  
        }

        if (fork() == 0){  
                //child process  
                if (execlp("rndc", "rndc", "thaw", RESPONSIBLE_ZONE, NULL) < 0 ) {  
                        perror("error on exec rndc thaw");  
                        exit(0);  
                }  
        }else{  
                //parent process  
                wait(&childpid);  
                printf("rndc thaw done, childpid = %d\n", childpid);  
        }
        pthread_mutex_unlock(&rrup_mxlock);
        return 0;
}

typedef struct offset_and_len {
        unsigned short offset;
        unsigned short len;
}offsetlen_t;
typedef struct olstack {
        struct offset_and_len component[8];
        int top;
}olstack_t;

void idns_rrup_updateinfo_set_domainname(idns_updateinfo_t *uinfo, 
        const char* prefix, unsigned int len)
{
        olstack_t st;
        offsetlen_t ol;
	st.top = 0;
        unsigned int cur_offset = strlen(PREFIX_TREE_ROOT);
        uinfo->RRdomainnamelen = strlen(RESPONSIBLE_ZONE) + len - cur_offset;
	unsigned int o, l, i = 0;
	unsigned int pre_offset = cur_offset;
	for ( ; cur_offset < len; ++cur_offset) {
                if(prefix[cur_offset] == '/') {
			ol.offset = pre_offset;
			ol.len = cur_offset - pre_offset;
			st.component[st.top++] = ol;
			pre_offset = cur_offset + 1;
		}
        }
	while (--st.top >= 0)
	{
		o = st.component[st.top].offset;
		l = st.component[st.top].len;
		memcpy(uinfo->RRdomainname + i, prefix + o, l);
		i += l;
		uinfo->RRdomainname[i++] = '.';
	}
	memcpy(uinfo->RRdomainname + i, RESPONSIBLE_ZONE, strlen(RESPONSIBLE_ZONE));
	return;
}