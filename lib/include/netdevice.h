#ifndef __NETDEVICE_H__
#define __NETDEVICE_H__

#include <stdlib.h>

#define NETDEVICE_ERROR -1
#define ETH_ADDR_LEN	6

/**
 * Script for allocate an eth address
 */
#define ETH_ALLOC(addr) u_int8_t *addr = (u_int8_t *)calloc(ETH_ADDR_LEN, sizeof(u_int8_t))

/**
 * Get device from pcap_findalldevs(),
 * than select one of it.
 * @param dev_sel_no '0' - select from terminal.
 * 'non0' - select directly from parameter
 * @param dev_name
 * @return 0 if success.
 * NETDEVICE_ERROR if error
 */
int netdevice_getdevice(const int dev_sel_no, char *dev_name);

/**
 * Convert string into byte array
 * @param eth_addr_str **:**:**:**:**:** format string
 * @return u_int8_t* point to eth_addr.
 * NULL if error
 */
u_int8_t *string_to_eth_addr(char *eth_addr_str);

#endif