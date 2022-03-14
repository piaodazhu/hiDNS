#include <stdio.h>
#include "updatezone.h"

int main() {
        char* hostname = "/edu/bit/lab3/papers/lee/";
        char* hostip = "121.121.121.121";
        idns_updateinfo_t *uinfo = idns_rrup_updateinfo_alloc();
        //idns_rrup_updateinfo_set_opcode_del(uinfo);
        idns_rrup_updateinfo_set_opcode_add(uinfo);
        idns_rrup_updateinfo_set_value(uinfo, hostip, strlen(hostip));
        idns_rrup_updateinfo_set_class_A(uinfo);
        uint tmp = strlen(hostname);
        idns_rrup_updateinfo_set_domainname(uinfo, hostname, tmp);
        idns_rrup_update_rr(uinfo);
        idns_rrup_flush();
        idns_rrup_updateinfo_free(uinfo);
        return 0;
}