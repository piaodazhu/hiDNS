/*
 * This file if part of dnsperf.
 *
 * Copyright (C) 2014 Cobblau
 *
 * dnsperf is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * dnsperf is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "eventsys.h"
#include <sys/epoll.h>


hidns_eventsys_t *hidns_eventsys = NULL;

typedef struct hidns_epoll_data_s {
    int                 fd;         /* epoll fd */
    struct fddata      *fdtab;      /* fd data in epoll */
    struct epoll_event *events;
    int                 fd_size;
} hidns_epoll_data_t;

static hidns_epoll_data_t *ep = NULL;

static int hidns_epoll_init(void)
{
    struct rlimit       limit;

    if ((ep = (hidns_epoll_data_t *)malloc(sizeof(hidns_epoll_data_t))) == NULL) {
        return -1;
    }

    /* create epoll */
    if ((ep->fd = epoll_create(MAX_EVENT_SOCKS)) < 0) {
        fprintf(stderr, "Error call epoll_create");
        goto fail_fd;
    }

    /* set fd ulimits */
    limit.rlim_cur = limit.rlim_max = MAX_EVENT_SOCKS;
    if (setrlimit(RLIMIT_NOFILE, &limit) == -1){
        fprintf(stderr, "Error: set ulimits fd to %d failure. reason:%s\n",
                MAX_EVENT_SOCKS, strerror(errno));
        goto fail_limit;
    }

    /* allocate epoll events */
    ep->fd_size = MAX_EVENT_SOCKS;
    if ((ep->events = (struct epoll_event *) calloc(ep->fd_size,
                                                    sizeof(struct epoll_event))) == NULL)
    {
        fprintf(stderr, "Error: alloc epoll event failure.");
        goto fail_limit;
    }

    /* create fdtable */
    if ((ep->fdtab = (struct fddata *) calloc(ep->fd_size,
                                              sizeof(struct fddata))) == NULL)
    {
        fprintf(stderr, "Error: alloc fddata failure.");
        goto fail_fdtab;
    }

    return 0;

fail_fdtab:
    free(ep->events);
fail_limit:
    close(ep->fd);
fail_fd:
    free(ep);
    ep = NULL;
    return -1;
}


static int hidns_epoll_destroy(void)
{
    if (ep) {
        free(ep->fdtab);
        free(ep->events);

        if (ep->fd) {
            close(ep->fd);
        }

        free(ep);

        ep = NULL;
    }

    return 0;
}


static int hidns_epoll_clear_fd(int fd, int mod)
{
    int                opcode;
    struct epoll_event ev;


    if (mod == MOD_RD) {
        ep->fdtab[fd].events &= ~EPOLLIN;
    } else if (mod == MOD_WR) {
        ep->fdtab[fd].events &= ~EPOLLOUT;
    }
    ev.events = ep->fdtab[fd].events;

    if (ep->fdtab[fd].events == 0) {
        opcode = EPOLL_CTL_DEL;
    } else {
        opcode = EPOLL_CTL_MOD;
    }

    if (epoll_ctl(ep->fd, opcode, fd, &ev) < 0) {
        fprintf(stderr, "Error epoll delete fd %d failure.", fd);
        return -1;
    }

    ep->fdtab[fd].cb[mod].arg = NULL;

    return 0;
}

static void *hidns_epoll_get_obj_by_fd(int fd, int mod)
{
    return ep->fdtab[fd].cb[mod].arg;
}


static int hidns_epoll_do_wait(long timeout)
{
    int i, fd;
    int nevents;
    hidns_event_ops_t *op;

    nevents = epoll_wait(ep->fd, ep->events, ep->fd_size, timeout);

    if (nevents < 0) {
        fprintf(stderr, "epoll_wait error:%s", strerror(errno));
        return -1;
    }

    for (i = 0; i < nevents; i++) {
        fd = ep->events[i].data.fd;
        // if (ep->events[i].events & (EPOLLERR | EPOLLHUP)) {
        //     // error
        //     op = (hidns_event_ops_t *) ep->fdtab[fd].cb[MOD_RD].arg;
        //     hidns_epoll_clear_fd(fd, MOD_RD);
        //     op->recv((void *) op);
        // }

        if (ep->events[i].events & (EPOLLOUT)) {
            op = (hidns_event_ops_t *) ep->fdtab[fd].cb[MOD_WR].arg;
            hidns_epoll_clear_fd(fd, MOD_WR);
            op->send((void *) op);
        }

        if (ep->events[i].events & (EPOLLIN | EPOLLERR | EPOLLHUP)) {
            op = (hidns_event_ops_t *) ep->fdtab[fd].cb[MOD_RD].arg;
            hidns_epoll_clear_fd(fd, MOD_RD);
            op->recv((void *) op);
        }
    }

    return 0;
}

static int hidns_epoll_set_fd(int fd, int mod, void *arg)
{
    int                opcode;
    struct epoll_event ev;


    if (fd > ep->fd_size) {
        // TODO: expand
    }

    if (ep->fdtab[fd].events == 0) {
        opcode = EPOLL_CTL_ADD;
    } else {
        opcode = EPOLL_CTL_MOD;
    }

    if (mod == MOD_RD) {
        ep->fdtab[fd].events = EPOLLIN;
    } else if(mod == MOD_WR) {
        ep->fdtab[fd].events = EPOLLOUT;
    } else {
        return -1;
    }

    ev.data.fd = fd;
    ev.events = ep->fdtab[fd].events;

    if (epoll_ctl(ep->fd, opcode, fd, &ev) < 0) {
        fprintf(stderr, "Error epoll add fd %d error. reason:%s\n", fd,
                strerror(errno));
        return -1;
    }

    ep->fdtab[fd].cb[mod].arg = arg;

    return 0;
}

static int hidns_epoll_is_fdset(int fd, int mod)
{
    if(((mod == MOD_RD) && ((ep->fdtab[fd].events & EPOLLIN) == EPOLLIN)) ||
       ((mod == MOD_WR) && ((ep->fdtab[fd].events & EPOLLOUT) == EPOLLOUT)))
    {
        return 1;
    }

    return 0;
}


static hidns_eventsys_t hidns_epoll_eventsys = {
    "epoll",
    hidns_epoll_init,
    hidns_epoll_do_wait,
    hidns_epoll_set_fd,
    hidns_epoll_clear_fd,
    hidns_epoll_destroy,
    hidns_epoll_get_obj_by_fd,
    hidns_epoll_is_fdset
};

int hidns_set_event_sys() {
    int set = -1;
    hidns_eventsys = &hidns_epoll_eventsys;
    set = 0;
    return set;
}
