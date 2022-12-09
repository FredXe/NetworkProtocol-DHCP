#ifndef __IP_H__
#define __IP_H__

#include <stdlib.h>

#include "netdevice.h"
#include "types.h"

#define IP_ADDR_LEN 4		 // Length of IPv4 address
#define ETH_IPV4	0x0008	 // Ethertype of IPv4

#define IP_ERROR	  -1	 // IP common error
#define IP_ERROR_NULL NULL	 // IP common error with NULL pointer

/**
 * Script for allocate an IP address
 */
#define IP_ALLOC(ip) byte *ip = (byte *)calloc(IP_ADDR_LEN, sizeof(byte))

/*================
 * Public Methods
 *================*/

#endif