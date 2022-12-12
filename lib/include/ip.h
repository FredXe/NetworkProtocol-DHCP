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

/*=================
 * Protocol Format
 *=================*/
typedef struct {
	// [1-4] Version. [5-8] Header length.
	byte ver_hlen;
	// [1-6] Differentiated Services. [7-8] Explicit Congestion Notification.
	byte DS_ECN;
	// Total length
	two_bytes length;

	// Identification
	two_bytes id;
	// [1-3] Flags. [4-16] Fragment Offset.
	two_bytes falg_frgofst;
	// Time to live
	byte ttl;
	// Protocol of upper layer
	byte protocol;
	// Header Checksum
	two_bytes hdr_chksum;

	// Source IP address
	ip_addr_t src_ip;
	// Destination IP address
	ip_addr_t dst_ip;
} ipv4_hdr_t;	// IPv4 header format

// Script to read version & hlen in ver_hlen
#define VER(ip_hdr)	 ((ip_hdr)->ver_hlen >> 4)
#define HLEN(ip_hdr) ((ip_hdr)->ver_hlen & 0x0F)

/*================
 * Public Methods
 *================*/

#endif