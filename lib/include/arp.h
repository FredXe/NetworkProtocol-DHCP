#ifndef __ARP_H__
#define __ARP_H__

#include "ip.h"
#include "netdevice.h"
#include "types.h"

#define ARP_ERROR -1   // ARP common error

#define ARP_ETH_TYPE   0x0100	// Hardware type of Ethernet in ARP
#define ARP_OP_REQUEST 0x0100	// ARP op code on request
#define ARP_OP_REPLY   0x0200	// ARP op code on reply

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
extern int arp_request(netdevice_t *device, byte *dst_ip_addr);
// extern int apr_send(const netdevice_t *netdevice, const byte *);

#endif