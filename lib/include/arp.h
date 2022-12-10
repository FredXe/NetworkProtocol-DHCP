#ifndef __ARP_H__
#define __ARP_H__

#include "ip.h"
#include "netdevice.h"
#include "types.h"

#define ETH_ARP 0x0608	 // Ethertype of ARP

#define ARP_ERROR		-1	   // ARP common error
#define ARP_UNKNOWN_MAC -2	   // ARP send() for unknown MAC address
#define ARP_ERROR_NULL	NULL   // ARP common error with NULL

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
extern int arp_reply(netdevice_t *device, byte *dst_eth_addr, byte *dst_ip_addr);
extern void arp_main(netdevice_t *device, const byte *packet, u_int length);
extern int arp_send(netdevice_t *device, byte *dst_ip_addr, two_bytes eth_type, byte *payload,
					u_int payload_len);
extern void arp_resend(netdevice_t *device);

#endif