#ifndef __IP_H__
#define __IP_H__

#include <stdlib.h>

#include "netdevice.h"
#include "types.h"

#define IP_ADDR_LEN 4	// Length of IPv4 address

#define IP_ERROR	  -1	 // IP common error
#define IP_ERROR_NULL NULL	 // IP common error with NULL pointer

/**
 * Script for allocate an IP address
 */
#define IP_ALLOC(ip) byte *ip = (byte *)calloc(IP_ADDR_LEN, sizeof(byte))

/*================
 * Public Methods
 *================*/
extern byte *ip_get_my_ip(netdevice_t *device);
extern byte *string_to_ip_addr(const char *ip_addr_str);

#endif