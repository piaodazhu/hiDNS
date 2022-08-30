#include "hidns_loadbalancer.h"
int lb_g_stop; /* 1: running   0: stop */
hidns_udp_forwarder_obj_t *lb_g_obj_array;
int lb_g_timeout;
forward_mapping_table_t fmt;
struct sockaddr_in server_addr;
struct sockaddr_in forward_addr[FWD_DIR_NUM];
int fwd_idx;

void sig_handler(int signo)
{
	switch (signo)
	{
	case SIGINT:
	case SIGTERM:
		lb_g_stop = 1;
		break;

	default:
		break;
	}
}

int not_implement(void *arg)
{
	printf("not implement\n");
	hidns_udp_forwarder_obj_t *obj = (hidns_udp_forwarder_obj_t *)arg;
	hidns_eventsys_set_fd(obj->fd, MOD_RD, obj);
	return 0;
}

int hidns_loadbalancer_init()
{
	lb_g_timeout = 500; // ms
	fwd_idx = 0;
	lb_g_obj_array = calloc(FWD_DIR_NUM, sizeof(hidns_udp_forwarder_obj_t));

	hidns_set_event_sys();
	hidns_eventsys_init();

	int listenfd;
	socklen_t addrlen = sizeof(server_addr);
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(5553);
	server_addr.sin_addr.s_addr = INADDR_ANY;
	listenfd = hidns_open_udp_socket(1, (struct sockaddr *)&server_addr, addrlen);

	forward_addr[0].sin_family = AF_INET;
	forward_addr[0].sin_port = htons(5554);
	forward_addr[0].sin_addr.s_addr = inet_addr("127.0.0.1");

	forward_addr[1].sin_family = AF_INET;
	forward_addr[1].sin_port = htons(5555);
	forward_addr[1].sin_addr.s_addr = inet_addr("127.0.0.1");

	hidns_udp_forwarder_obj_t *listenobj = (hidns_udp_forwarder_obj_t*)malloc(sizeof(hidns_udp_forwarder_obj_t));
	listenobj->fd = listenfd;
	listenobj->ops.send = not_implement;
	listenobj->ops.recv = clientrecv;
	hidns_eventsys_set_fd(listenfd, MOD_RD, listenobj);

	int i;
	hidns_udp_forwarder_obj_t *obj;
	for (i = 0; i < FWD_DIR_NUM; i++)
	{
		obj = &lb_g_obj_array[i];
		obj->fd = hidns_open_udp_socket(2, (const struct sockaddr *)&forward_addr[i], sizeof(forward_addr[i]));
		obj->listenfd = listenfd;
		obj->ops.send = not_implement;
		obj->ops.recv = innerrecv;
		hidns_eventsys_set_fd(obj->fd, MOD_RD, obj);
	}

	fmt.tabsize = MAX_MAP_SIZE;
	fmt.cur_idx = 0;
	for (i = 0; i < fmt.tabsize; i++) {
		fmt.entry[i].flag = LB_F_UNUSED;
	}

	return 0;
}

int innerrecv(void *arg)
{
	// printf("innerrecv called\n");
	hidns_udp_forwarder_obj_t *obj = (hidns_udp_forwarder_obj_t *)arg;

	int ret = 0;
	unsigned char buf[INS_UDPMAXSIZE];
	ret = recv(obj->fd, buf, INS_UDPMAXSIZE, 0);
	if (ret < 0)
	{
		// printf("inner recv error\n");
		if (errno != EWOULDBLOCK && errno != EAGAIN)
		{
			// perror("tag11\n");
			goto error_out;
		}

		if (hidns_eventsys_set_fd(obj->fd, MOD_RD, obj) == -1)
		{
			// printf("tag12\n");
			goto error_out;
		}
		return 0;
	}

	int idx = buf[0] << 8 | buf[1];
	buf[0] = fmt.entry[idx].qid >> 8;
	buf[1] = fmt.entry[idx].qid & 0xff;
	fmt.entry[idx].flag = LB_F_UNUSED;

	ret = sendto(obj->listenfd, buf, ret, 0, (const struct sockaddr *)&fmt.entry[idx].clientaddr, sizeof(struct sockaddr_in));
	if (ret < 0)
	{
		// printf("client send error\n");
		if (errno != EWOULDBLOCK && errno != EAGAIN)
		{
			goto error_out;
		}

		if (hidns_eventsys_set_fd(obj->fd, MOD_WR, obj) == -1)
		{
			goto error_out;
		}
		return 0;
	}

	if (hidns_eventsys_set_fd(obj->fd, MOD_RD, obj) == -1)
	{
		fprintf(stderr, "Error set read fd:%d\n", obj->fd);
		// printf("tag8\n");
		goto error_out;
	}

	// close(obj->fd);
	// obj->state = LB_F_UNUSED;
	// printf("innerrecv finish\n");
	return 0;
error_out:
// printf("tag18\n");
	return 0;
}

int clientrecv(void *arg)
{
	// printf("clientrecv called\n");
	hidns_udp_forwarder_obj_t *obj = (hidns_udp_forwarder_obj_t *)arg;
	timeval_t now;
	gettimeofday(&now, NULL);

	int ret = 0, i = 0;
	unsigned char buf[INS_UDPMAXSIZE];
	struct sockaddr_in remote;
	socklen_t addrlen = sizeof(struct sockaddr);

	ret = recvfrom(obj->fd, buf, INS_UDPMAXSIZE, 0, (struct sockaddr *)&remote, &addrlen);
	if (ret < 0)
	{
		// printf("client recv error\n");
		if (errno != EWOULDBLOCK && errno != EAGAIN)
		{
			// perror("tag1\n");
			goto error_out;
		}

		if (hidns_eventsys_set_fd(obj->fd, MOD_RD, obj) == -1)
		{
			// printf("tag2\n");
			goto error_out;
		}
		return 0;
	}
// printf("tag1\n");
	// find a space to do the mapping
	int found = 0, idx = 0;

	int oldest_idx = fmt.cur_idx;
	timeval_t oldest_entry = fmt.entry[fmt.cur_idx].lifetime;

	for (i = 0; i < fmt.tabsize; i++) {
		idx = (fmt.cur_idx + i) % fmt.tabsize;
		if (fmt.entry[idx].flag == LB_F_UNUSED || 
			hidns_timer_cmp(now, fmt.entry[idx].lifetime)) 
		{
			found = 1;
			break;
		}	
		if (hidns_timer_cmp(oldest_entry, fmt.entry[idx].lifetime)) {
			oldest_entry = fmt.entry[idx].lifetime;
			oldest_idx = idx;
		}
	}
// printf("tag2\n");
// printf("i = %d\n", i);
	if (found = 0) {
		printf("busy");
		// time cmp algorithm
		idx = oldest_idx;
	}
	// fmt.entry[idx].flag = LB_F_ISUSED;
	fmt.entry[idx].lifetime = hidns_timer_add_long(now, lb_g_timeout*1000);
	fmt.entry[idx].clientaddr = remote;
	fmt.entry[idx].qid = buf[0] << 8 | buf[1];
	fmt.cur_idx = (idx + 1) % fmt.tabsize;
	buf[0] = idx >> 8;
	buf[1] = idx & 0xff;
	
	// find a new forward obj
	hidns_udp_forwarder_obj_t *fwd_obj = &lb_g_obj_array[fwd_idx % FWD_DIR_NUM];
	ret = send(fwd_obj->fd, buf, ret, 0);
	// ret = sendto(obj->fd, buf, ret, 0, (struct sockaddr *)&remote, addrlen);
	if (ret < 0)
	{
		// printf("client send error\n");
		if (errno != EWOULDBLOCK && errno != EAGAIN)
		{
			// perror("tag6\n");
			goto error_out;
		}

		if (hidns_eventsys_set_fd(fwd_obj->fd, MOD_WR, fwd_obj) == -1)
		{
			// printf("tag7\n");
			goto error_out;
		}
		return 0;
	}
	if (hidns_eventsys_set_fd(obj->fd, MOD_RD, obj) == -1)
	{
		fprintf(stderr, "Error set read fd:%d\n", obj->fd);
		// printf("tag9\n");
		goto error_out;
	}
	// printf("fwdidx=%d\n", fwd_idx);
	fwd_idx = (fwd_idx + 1) % FWD_DIR_NUM;
	return 0;
error_out:
// printf("tag5\n");	
	return 0;
}

static int hidns_process_timeout_mapping()
{
	int i;
	forward_mapping_entry_t *entry;
	timeval_t now;

	/* Deal with timeout */
	gettimeofday(&now, NULL);
	for (i = 0; i < MAX_MAP_SIZE; i++)
	{

		entry = &fmt.entry[i];

		if (entry->flag == LB_F_UNUSED)
		{
			continue;
		}

		if (hidns_timer_cmp(now, entry->lifetime) > 0)
		{
			entry->flag = LB_F_UNUSED;
		}
	}

	return 0;
}

int main()
{
	// read configure
	// initialize
	hidns_loadbalancer_init();
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while (lb_g_stop == 0)
	{
		hidns_eventsys_dispatch(lb_g_timeout);
		// hidns_process_timeout_mapping();
	}
	return 0;
}