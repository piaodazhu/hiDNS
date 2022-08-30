#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../cJSON/cJSON.h"

int main()
{
	char config_buf[4096];
	FILE *fp = fopen("config.json", "rb");
	size_t config_len = fread(config_buf, 1, 4096, fp);
	fclose(fp);
	config_buf[config_len] = 0;

	cJSON *config_json = cJSON_Parse(config_buf);
	if (config_json == NULL)
	{
		const char *error_ptr = cJSON_GetErrorPtr();
		if (error_ptr != NULL)
		{
			fprintf(stderr, "Error before: %s\n", error_ptr);
		}
		exit(1);
	}

	const cJSON *global_block = NULL;
	const cJSON *global_ins_local = NULL;
	const cJSON *global_ins_remote = NULL;
	const cJSON *global_dns_module = NULL;
	global_block = cJSON_GetObjectItemCaseSensitive(config_json, "GLOBAL");
	cJSON *nickname_item = cJSON_GetObjectItemCaseSensitive(global_block, "nickname");
	cJSON *serveport_item = cJSON_GetObjectItemCaseSensitive(global_block, "serveport");
	printf("[nickname] %s\n", nickname_item->valuestring);
	printf("[serveport] %d\n", serveport_item->valueint);

	global_ins_local = cJSON_GetObjectItemCaseSensitive(config_json, "INS_LOCAL");
	cJSON *prefix_array = cJSON_GetObjectItemCaseSensitive(global_ins_local, "prefix");
	cJSON *prefix_item = NULL;
	cJSON_ArrayForEach(prefix_item, prefix_array)
	{
		printf("[prefix] %s\n", prefix_item->valuestring);
	}

	global_ins_remote = cJSON_GetObjectItemCaseSensitive(config_json, "INS_REMOTE");

	global_dns_module = cJSON_GetObjectItemCaseSensitive(config_json, "DNS_REMOTE");


	return 0;
}