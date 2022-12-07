#ifndef __ARP_H__
#define __ARP_H__

#include "ip.h"
#include "netdevice.h"
#include "types.h"

/*=================
 * Protocol Format
 *=================*/
typedef struct {
	two_bytes hdr_type;				   // Harware type
	two_bytes proto_type;			   // Protocol type
	byte hdr_addr_len;				   // Length of MAC address
	byte ip_addr_len;				   // Length of IP address
	two_bytes op;					   // Operation
	byte src_eth_addr[ETH_ADDR_LEN];   // Source MAC address
	byte src_ip_addr[IP_ADDR_LEN];	   // Source IP address
	byte dst_eth_addr[ETH_ADDR_LEN];   // Destination MAC address
	byte dst_ip_addr[IP_ADDR_LEN];	   // Destination IP address
} arp_t;							   // ARP packet format

/*================
 * Public Methods
 *================*/

#endif