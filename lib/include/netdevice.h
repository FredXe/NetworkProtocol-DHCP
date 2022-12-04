#ifndef __NETDEVICE_H__
#define __NETDEVICE_H__

#include <stdlib.h>

#define ETH_ADDR_LEN 6

#define ETH_ALLOC(addr) u_int8_t *addr = (u_int8_t *)calloc(ETH_ADDR_LEN, sizeof(u_int8_t))

/**
 * @brief Convert string into byte array
 *
 * @param eth_addr_str **:**:**:**:**:** format string
 * @return u_int8_t* point to eth_addr
 */
u_int8_t *string_to_eth_addr(char *eth_addr_str);

int netdevice_getdevice();

#endif