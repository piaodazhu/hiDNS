#include "hidns_loadbalancer.h"
int lb_g_stop; /* 1: running   0: stop */
hidns_udp_forwarder_obj_t *lb_g_obj_array;
int lb_g_obj_idx;
int lb_g_timeout;

void silb_g_handler(int signo)
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
	lb_g_timeout = 50; // ms
	lb_g_obj_idx = 0;
	lb_g_obj_array = calloc(MAX_OBJ_NUM, sizeof(hidns_udp_forwarder_obj_t));

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
	forward_addr[0].sin_addr.s_addr = INADDR_ANY;

	forward_addr[1].sin_family = AF_INET;
	forward_addr[1].sin_port = htons(5554);
	forward_addr[1].sin_addr.s_addr = INADDR_ANY;

	hidns_udp_forwarder_obj_t *listenobj = (hidns_udp_forwarder_obj_t *)malloc(sizeof(hidns_udp_forwarder_obj_t));
	listenobj->fd = listenfd;
	listenobj->ops.send = not_implement;
	listenobj->ops.recv = clientrecv;
	hidns_eventsys_set_fd(listenfd, MOD_RD, listenobj);

	int i;
	hidns_udp_forwarder_obj_t *obj;
	for (i = 0; i < MAX_OBJ_NUM; i++)
	{
		obj = &lb_g_obj_array[i];
		obj->fd = -1;
		obj->listenfd = listenfd;
		obj->ops.send = not_implement;
		obj->ops.recv = innerrecv;
		obj->state = LB_F_UNUSED;
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
		printf("inner recv error\n");
		if (errno != EWOULDBLOCK && errno != EAGAIN)
		{
			goto error_out;
		}

		if (hidns_eventsys_set_fd(obj->fd, MOD_RD, obj) == -1)
		{
			goto error_out;
		}
		return 0;
	}

	ret = sendto(obj->listenfd, buf, ret, 0, (const struct sockaddr *)&obj->clientaddr, sizeof(obj->clientaddr));
	if (ret < 0)
	{
		printf("client send error\n");
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
	close(obj->fd);
	obj->state = LB_F_UNUSED;
	// printf("innerrecv finish\n");
error_out:
	return 0;
}

int clientrecv(void *arg)
{
	// printf("clientrecv called\n");
	hidns_udp_forwarder_obj_t *obj = (hidns_udp_forwarder_obj_t *)arg;
	static int idx = 0;

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
			goto error_out;
		}

		if (hidns_eventsys_set_fd(obj->fd, MOD_RD, obj) == -1)
		{
			goto error_out;
		}
		return 0;
	}

	// find a new forward obj
	hidns_udp_forwarder_obj_t *fwd_obj;
	for (i = 0; i < MAX_OBJ_NUM; i++)
	{
		fwd_obj = &lb_g_obj_array[(i + lb_g_obj_idx) % MAX_OBJ_NUM];
		// printf("obj %d state is : %d\n", (i + lb_g_obj_idx) % MAX_OBJ_NUM, fwd_obj->state);
		if (fwd_obj->state == LB_F_ISUSED)
		{
			continue;
		}
		break;
	}
	if (i == MAX_OBJ_NUM)
	{
		// printf("busy..\n");
		lb_g_obj_idx = 0;
		goto error_out;
	}
	// printf("find one\n");
	lb_g_obj_idx = (i + lb_g_obj_idx) % MAX_OBJ_NUM;
	fwd_obj->fd = hidns_open_udp_socket(2, (const struct sockaddr *)&forward_addr[idx], sizeof(forward_addr[idx]));
	// if (fwd_obj->fd <= 0 || fwd_obj->fd > 30)
	// 	printf("create new fd:%d\n", fwd_obj->fd);
	fwd_obj->clientaddr = remote;
	timeval_t now;
	gettimeofday(&now, NULL);
	fwd_obj->lifetime = hidns_timer_add_long(now, lb_g_timeout * 1000);

	ret = send(fwd_obj->fd, buf, ret, 0);
	if (ret < 0)
	{
		// printf("client send error\n");
		if (errno != EWOULDBLOCK && errno != EAGAIN)
		{
			goto error_out;
		}

		if (hidns_eventsys_set_fd(fwd_obj->fd, MOD_WR, fwd_obj) == -1)
		{
			goto error_out;
		}
		return 0;
	}
	if (hidns_eventsys_set_fd(fwd_obj->fd, MOD_RD, fwd_obj) == -1)
	{
		fprintf(stderr, "Error set read fd:%d\n", fwd_obj->fd);
		goto error_out;
	}
	fwd_obj->state = LB_F_ISUSED;

	if (hidns_eventsys_set_fd(obj->fd, MOD_RD, obj) == -1)
	{
		fprintf(stderr, "Error set read fd:%d\n", obj->fd);
		goto error_out;
	}
	// printf("clientrecv finish\n");
error_out:
	idx = (idx + 1) % 1;
	return 0;
}

static int hidns_process_timeout_obj()
{
	int i;
	hidns_udp_forwarder_obj_t *obj;
	timeval_t now, diff;

	/* Deal with timeout */
	gettimeofday(&now, NULL);
	for (i = 0; i < MAX_OBJ_NUM; i++)
	{

		obj = &lb_g_obj_array[i];

		if (obj->state == LB_F_UNUSED)
		{
			continue;
		}

		if (hidns_timer_cmp(now, obj->lifetime) > 0)
		{
			/* delete timeouted context */
	// printf("delete fd %d\n", obj->fd);
			hidns_eventsys_clear_fd(obj->fd, MOD_RD);
			close(obj->fd);
			obj->state = LB_F_UNUSED;
		}
	}

	return 0;
}

int main()
{
	// read configure
	// initialize
	hidns_loadbalancer_init();
	signal(SIGINT, silb_g_handler);
	signal(SIGTERM, silb_g_handler);

	while (lb_g_stop == 0)
	{
		hidns_eventsys_dispatch(lb_g_timeout);
		hidns_process_timeout_obj();
	}
	return 0;
}