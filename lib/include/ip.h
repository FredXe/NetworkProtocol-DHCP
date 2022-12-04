#ifndef __IP_H__
#define __IP_H__

#include <stdlib.h>

#define IP_ADDR_LEN 4

/*
 *script for allocate an IP address
 */
#define IP_ALLOC(ip) u_int8_t *ip = (u_int8_t *)calloc(IP_ADDR_LEN, sizeof(u_int8_t))

#endif