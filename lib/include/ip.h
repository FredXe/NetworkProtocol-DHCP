#ifndef __IP_H__
#define __IP_H__

#include <stdlib.h>
#include <string.h>

#include "netdevice.h"
#include "types.h"

#define IP_ADDR_LEN		4							 // Length of IPv4 address
#define ETH_IPV4		0x0008						 // Ethertype of IPv4
#define IP_VERSION		4							 // IP version
#define IP_MIN_HLEN		5							 // Minmal length of IP header (5*4=20bytes)
#define IP_MAX_TTL		255							 // Maximum value of Time To Live
#define MAX_IP_DATA_LEN (MTU - sizeof(ipv4_hdr_t))	 // Maximum Length of IP data

#define IP_ERROR	  -1	 // IP common error
#define IP_ERROR_NULL NULL	 // IP common error with NULL pointer

typedef void (*ip_handler)(const byte *packet, const u_int length);

/**
 * Script for allocate an IP address
 */
#define IP_ALLOC(ip) byte *ip = (byte *)calloc(IP_ADDR_LEN, sizeof(byte))

typedef struct {
	byte my_ip_addr[IP_ADDR_LEN];	// My IP address
	byte gateway_d[IP_ADDR_LEN];	// Default gateway
	byte dns_server[IP_ADDR_LEN];	// DNS server
	byte subnet[IP_ADDR_LEN];		// Subnet
	u_int subnet_mask;				// Subnet mask e.g.:24
} ipv4_info_t;						// IPv4 information struct

typedef struct ip_protocol ip_protocol_t;

struct ip_protocol {
	byte protocol;		   // IP protocol number
	ip_handler callback;   // Callback function of upper layer
	ip_protocol_t *next;   // Next element
};

/*=================
 * Protocol Format
 *=================*/
typedef struct {
	// [1-4] Version. [5-8] Header length.
	byte ver_hlen;
	// [1-6] Differentiated Services. [7-8] Explicit Congestion Notification.
	byte DS_ECN;
	// Total length
	two_bytes total_len;

	// Identification
	two_bytes id;
	// [1-3] Flags. [4-16] Fragment Offset.
	two_bytes flag_frgofst;
	// Time to live
	byte ttl;
	// IP protocol number
	byte protocol;
	// Header Checksum
	two_bytes hdr_chksum;

	// Source IP address
	byte src_ip[IP_ADDR_LEN];
	// Destination IP address
	byte dst_ip[IP_ADDR_LEN];
} ipv4_hdr_t;	// IPv4 header format

// Script to read version & hlen in ver_hlen
#define VER(ip_hdr)			((ip_hdr)->ver_hlen >> 4)
#define HLEN(ip_hdr)		((ip_hdr)->ver_hlen & 0x0F)
#define VER_HLEN(ver, hlen) (((ver) << 4) + hlen)

#define IP_COPY(dst, src) (memcpy((dst), (src), IP_ADDR_LEN))

/*================
 * Public Methods
 *================*/
extern netdevice_t *ip_init();
extern const ipv4_hdr_t ip_hdr_maker(const byte protocol, const byte *src_ip, const byte *dst_ip,
									 const u_int data_len);
extern int is_my_subnet(const byte *ip);
extern int ip_chk_proto_list(const byte protocol);
extern int ip_add_protocol(const byte protocol, ip_handler callback);
extern int ip_send(const ipv4_hdr_t *ip_hdr, const byte *data, const u_int data_len);
extern void ip_main(netdevice_t *device, const byte *packet, const u_int length);
extern void ip_close();

#endif