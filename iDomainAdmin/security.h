#ifndef IDNS_SECURITY_H
#define IDNS_SECURITY_H
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct clientcertificate {
        u_int64_t entity_id;
        u_int32_t cert_expiretime;
        u_int16_t algorithm;
        u_int16_t keybuflen;
        char* keybuf;
}clientcertificate_t;


void onewayhash128(char *x);
int checksignature();
int checktoken_hash128(char *start, char *end, int k);


#endif