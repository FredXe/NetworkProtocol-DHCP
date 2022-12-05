#ifndef __IP_H__
#define __IP_H__

#include <stdlib.h>

#define IP_ERROR	  -1
#define IP_ERROR_NULL NULL
#define IP_ADDR_LEN	  4

/**
 * Script for allocate an IP address
 */
#define IP_ALLOC(ip) u_int8_t *ip = (u_int8_t *)calloc(IP_ADDR_LEN, sizeof(u_int8_t))

u_int8_t *string_to_ip_addr(char *ip_addr_str);

#endif