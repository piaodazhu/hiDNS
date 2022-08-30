#ifndef _EVENTS_H
#define _EVENTS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>


#define MOD_RD   0
#define MOD_WR   1

#define MAX_EVENT_SOCKS  10000

/* info about one given fd */
struct fddata {
    int events;
    struct {
        void  *arg;
    } cb[2];
};

typedef struct hidns_event_ops_s {
    int (*send)(void *arg);
    int (*recv)(void *arg);
} hidns_event_ops_t;


typedef struct hidns_eventsys_s {
    const char *name;
    int   (*init)(void);
    int   (*dispatch)(long timeout);
    int   (*set_fd)(int fd, int mod, void *p);
    int   (*clear_fd)(int fd, int mod);
    int   (*destroy)(void);
    void *(*get_obj_by_fd)(int fd, int mod);
    int   (*is_fdset)(int fd, int mod);
} hidns_eventsys_t;


extern hidns_eventsys_t *hidns_eventsys;

int hidns_set_event_sys();
#define hidns_eventsys_init()                 hidns_eventsys->init()
#define hidns_eventsys_destroy()              hidns_eventsys->destroy()
#define hidns_eventsys_dispatch(t)            hidns_eventsys->dispatch(t)
#define hidns_eventsys_is_fdset(fd)           hidns_eventsys->is_fdset(fd)
#define hidns_eventsys_clear_fd(fd, mod)      hidns_eventsys->clear_fd(fd, mod)
#define hidns_eventsys_set_fd(fd, mod, obj)   hidns_eventsys->set_fd(fd, mod, obj)
#define hidns_eventsys_get_obj_by_fd(fd, mod) hidns_eventsys->get_obj_by_fd(fd, mod)

#endif
