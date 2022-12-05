/**
 * @file netdevice.h
 * Define the protocol and tools below 2nd layer:
 * Ethernet, link device etc.
 */
#ifndef __NETDEVICE_H__
#define __NETDEVICE_H__

#include <stdlib.h>

#define NETDEVICE_ERROR		 -1
#define NETDEVICE_ERROR_NULL NULL
#define ETH_ADDR_LEN		 6

/**
 * Script for allocate an eth address
 */
#define ETH_ALLOC(addr) u_int8_t *addr = (u_int8_t *)calloc(ETH_ADDR_LEN, sizeof(u_int8_t))

/*=================
 * Protocol Format
 *=================*/
typedef struct {
	u_int8_t eth_dst[ETH_ADDR_LEN];	  // Destination MAC address
	u_int8_t eth_src[ETH_ADDR_LEN];	  // Source MAC address
	u_int16_t eth_type;				  // Ethertype
} eth_hdr_t;						  // Ethernet header

int netdevice_getdevice(const int dev_sel_no, char *dev_name);

u_int8_t *string_to_eth_addr(char *eth_addr_str);

#endif