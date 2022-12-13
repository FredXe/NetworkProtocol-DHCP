#ifndef __UDP_H__
#define __UDP_H__

#include "netdevice.h"
#include "util.h"

#define IP_PROTO_UDP 0x11	// IP protocol number of UDP

#define UDP_ERROR	   -1	  // UDP common error
#define UDP_ERROR_NULL NULL	  // UDP common error with NULL

/*=================
 * Protocol Format
 *=================*/
typedef struct {
	two_bytes src_port;	  // Source port
	two_bytes dst_port;	  // Destination port
	two_bytes length;	  // Total Length of UDP header + data
	two_bytes checksum;	  // Checksum. Optional in IPv4, carries all-zero if unused
} udp_hdr_t;			  // UDP header protocol format

typedef struct {
	byte src_ip[IP_ADDR_LEN];	// Source IP address
	byte dst_ip[IP_ADDR_LEN];	// Destination IP address
	byte zeros;					// 0x00
	byte IP_proto;				// IP protocol number
	two_bytes udp_len;			// Length of UDP datagram
} udp_pseudo_hdr_t;				// UDP pseudo header format

/*================
 * Public Methods
 *================*/
extern two_bytes udp_checksum(udp_pseudo_hdr_t pseudo_hdr, const byte *udp_data);
extern udp_pseudo_hdr_t udp_pseudo_hdr_maker(const byte *src_ip, const byte *dst,
											 two_bytes udp_len);
extern void test_udp_callback(const byte *data, u_int length);
extern netdevice_t *udp_init();

#endif