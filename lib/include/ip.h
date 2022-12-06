#ifndef __IP_H__
#define __IP_H__

#include <stdlib.h>

#include "types.h"

#define IP_ERROR	  -1
#define IP_ERROR_NULL NULL
#define IP_ADDR_LEN	  4

/**
 * Script for allocate an IP address
 */
#define IP_ALLOC(ip) byte *ip = (byte *)calloc(IP_ADDR_LEN, sizeof(byte))

extern byte *string_to_ip_addr(const char *ip_addr_str);

#endif