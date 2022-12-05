#ifndef __IP_H__
#define __IP_H__

#include <stdlib.h>

#define IP_ADDR_LEN 4

/**
 *	Script for allocate an IP address
 */
#define IP_ALLOC(ip) u_int8_t *ip = (u_int8_t *)calloc(IP_ADDR_LEN, sizeof(u_int8_t))

/**
 * Convert string into byte array
 * @param ip_addr_str *.*.*.* format string
 * @return u_int8_t* point to ip_addr
 * 	NULL if error
 */
u_int8_t *string_to_ip_addr(char *ip_addr_str);

#endif