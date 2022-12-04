#ifndef __NETDEVICE_H__
#define __NETDEVICE_H__

#include <stdlib.h>

#define ETH_ADDR_LEN 6

#define ETH_ALLOC(addr) u_int8_t *addr = (u_int8_t *)calloc(ETH_ADDR_LEN, sizeof(u_int8_t))

/**
 *	Convert string into byte array
 *	@param eth_addr_str **:**:**:**:**:** format string
 */
u_int8_t *string_to_eth_addr(char *eth_addr_str);

#endif
