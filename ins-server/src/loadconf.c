#include "loadconf.h"
#include "../cJSON/cJSON.h"

int load_conf_json(char *filename)
{
	char config_buf[1024*1024];
	FILE *fp = fopen(filename, "rb");
	if (fp == NULL) {
#ifdef	INSSLOG_PRINT
		printf("[x] can't find config.json. exit.\n");
#endif
#ifdef	INSSLOG_SYSLOG
		syslog(LOG_ERR, "can't find config.json. exit.\n");
#endif
		exit(1);
	}
	size_t config_len = fread(config_buf, 1, 1024*1024, fp);
	fclose(fp);
	config_buf[config_len] = 0;

	cJSON *config_json = cJSON_Parse(config_buf);
	if (config_json == NULL)
	{
#ifdef	INSSLOG_PRINT
		printf("[x] can't parse config.json. exit.\n");
#endif
#ifdef	INSSLOG_SYSLOG
		syslog(LOG_ERR, "can't parse config.json. exit.\n");
#endif
		exit(2);
	}

	const cJSON *global_block = NULL;
	const cJSON *global_ins_local = NULL;
	const cJSON *global_ins_remote_array = NULL;
	const cJSON *global_ins_remote_item = NULL;
	const cJSON *global_dns_module_array = NULL;
	const cJSON *global_dns_module_item = NULL;

	// first block
	global_block = cJSON_GetObjectItemCaseSensitive(config_json, "GLOBAL");
	
	cJSON *nickname_item = cJSON_GetObjectItemCaseSensitive(global_block, "nickname");
	memset(GLOBAL_NICKNAME, 0, 256);
	memcpy(GLOBAL_NICKNAME, nickname_item->valuestring, strlen(nickname_item->valuestring));	
#ifdef	INSSLOG_PRINT
	printf("read conf [nickname]: %s\n", nickname_item->valuestring);
#endif
#ifdef	INSSLOG_SYSLOG
	syslog(LOG_INFO, "read conf [nickname]: %s\n", nickname_item->valuestring);
#endif

	cJSON *domainname_item = cJSON_GetObjectItemCaseSensitive(global_block, "domainname");
	memset(GLOBAL_DOMAINNAME, 0, 256);
	memcpy(GLOBAL_DOMAINNAME, domainname_item->valuestring, strlen(domainname_item->valuestring));
#ifdef	INSSLOG_PRINT
	printf("read conf [domainname]: %s\n", domainname_item->valuestring);
#endif
#ifdef	INSSLOG_SYSLOG
	syslog(LOG_INFO, "read conf [domainname]: %s\n", domainname_item->valuestring);
#endif

	GLOBAL_LOCALADDR.sin_family = AF_INET;
	cJSON *serveip_item = cJSON_GetObjectItemCaseSensitive(global_block, "serveip");
	GLOBAL_LOCALADDR.sin_addr.s_addr = inet_addr(serveip_item->valuestring);
#ifdef	INSSLOG_PRINT
	printf("read conf [serveip]: %s\n", serveip_item->valuestring);
#endif
#ifdef	INSSLOG_SYSLOG
	syslog(LOG_INFO, "read conf [serveip]: %s\n", serveip_item->valuestring);
#endif

	cJSON *serveport_item = cJSON_GetObjectItemCaseSensitive(global_block, "serveport");
	GLOBAL_LOCALADDR.sin_port = htons((uint16_t)serveport_item->valueint);
#ifdef	INSSLOG_PRINT
	printf("read conf [serveport]: %d\n", serveport_item->valueint);
#endif
#ifdef	INSSLOG_SYSLOG
	syslog(LOG_INFO, "read conf [serveport]: %d\n", serveport_item->valueint);
#endif

	cJSON *authorizer_item = cJSON_GetObjectItemCaseSensitive(global_block, "authorizer");
	memset(GLOBAL_AUTHORIZER, 0, 256);
	memcpy(GLOBAL_AUTHORIZER, authorizer_item->valuestring, strlen(authorizer_item->valuestring));
#ifdef	INSSLOG_PRINT
	printf("read conf [authorizer]: %s\n", authorizer_item->valuestring);
#endif
#ifdef	INSSLOG_SYSLOG
	syslog(LOG_INFO, "read conf [authorizer]: %s\n", authorizer_item->valuestring);
#endif

	const cJSON *resolver_item = NULL;
	const cJSON *dstport_item = NULL;
	const cJSON *prefix_array = NULL;
	const cJSON *prefix_item = NULL;
	struct sockaddr_in addr_buf;
	addr_buf.sin_family = AF_INET;
	
	rkt_init();

	// second block
	global_ins_local = cJSON_GetObjectItemCaseSensitive(config_json, "INS_PATH_LOCAL");

	resolver_item = cJSON_GetObjectItemCaseSensitive(global_ins_local, "resolver");
	dstport_item = cJSON_GetObjectItemCaseSensitive(global_ins_local, "dstport");
	prefix_array = cJSON_GetObjectItemCaseSensitive(global_ins_local, "prefix");

	addr_buf.sin_addr.s_addr = inet_addr(resolver_item->valuestring);
	addr_buf.sin_port = htons((uint16_t)dstport_item->valueint);
	cJSON_ArrayForEach(prefix_item, prefix_array)
	{
		rkt_add_path(prefix_item->valuestring, strlen(prefix_item->valuestring), 
						&addr_buf, sizeof(struct sockaddr_in), ins_local_module);
		
#ifdef	INSSLOG_PRINT
		printf("read conf [prefix] %s --> %s:%d\n", prefix_item->valuestring, resolver_item->valuestring, dstport_item->valueint);
#endif
#ifdef	INSSLOG_SYSLOG
		syslog(LOG_INFO, "read conf [prefix] %s --> %s:%d\n", prefix_item->valuestring, resolver_item->valuestring, dstport_item->valueint);
#endif
	}

	// third block
	global_ins_remote_array = cJSON_GetObjectItemCaseSensitive(config_json, "INS_PATH_REMOTE");
	cJSON_ArrayForEach(global_ins_remote_item, global_ins_remote_array)
	{
		resolver_item = cJSON_GetObjectItemCaseSensitive(global_ins_remote_item, "resolver");
		dstport_item = cJSON_GetObjectItemCaseSensitive(global_ins_remote_item, "dstport");
		prefix_array = cJSON_GetObjectItemCaseSensitive(global_ins_remote_item, "prefix");

		addr_buf.sin_addr.s_addr = inet_addr(resolver_item->valuestring);
		addr_buf.sin_port = htons((uint16_t)dstport_item->valueint);
		cJSON_ArrayForEach(prefix_item, prefix_array)
		{
			rkt_add_path(prefix_item->valuestring, strlen(prefix_item->valuestring), 
						&addr_buf, sizeof(struct sockaddr_in), ins_remote_module);
			
#ifdef	INSSLOG_PRINT
			printf("read conf [prefix] %s --> %s:%d\n", prefix_item->valuestring, resolver_item->valuestring, dstport_item->valueint);
#endif
#ifdef	INSSLOG_SYSLOG
			syslog(LOG_INFO, "read conf [prefix] %s --> %s:%d\n", prefix_item->valuestring, resolver_item->valuestring, dstport_item->valueint);
#endif
		}
	}

	// third block
	global_dns_module_array = cJSON_GetObjectItemCaseSensitive(config_json, "DNS_PATH");
	cJSON_ArrayForEach(global_dns_module_item, global_dns_module_array)
	{
		resolver_item = cJSON_GetObjectItemCaseSensitive(global_dns_module_item, "resolver");
		dstport_item = cJSON_GetObjectItemCaseSensitive(global_dns_module_item, "dstport");
		prefix_array = cJSON_GetObjectItemCaseSensitive(global_dns_module_item, "prefix");

		addr_buf.sin_addr.s_addr = inet_addr(resolver_item->valuestring);
		addr_buf.sin_port = htons((uint16_t)dstport_item->valueint);
		cJSON_ArrayForEach(prefix_item, prefix_array)
		{
			rkt_add_path(prefix_item->valuestring, strlen(prefix_item->valuestring), 
						&addr_buf, sizeof(struct sockaddr_in), dns_module);
			
#ifdef	INSSLOG_PRINT
			printf("read conf [prefix] %s --> %s:%d\n", prefix_item->valuestring, resolver_item->valuestring, dstport_item->valueint);
#endif
#ifdef	INSSLOG_SYSLOG
			syslog(LOG_INFO, "read conf [prefix] %s --> %s:%d\n", prefix_item->valuestring, resolver_item->valuestring, dstport_item->valueint);
#endif
		}
	}

	rkt_finish_build();

	return 0;
}