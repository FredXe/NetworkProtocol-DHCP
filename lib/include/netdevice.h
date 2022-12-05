/**
 * @file netdevice.h
 * Define the protocol and tools below 2nd layer:
 * Ethernet, link device etc.
 */
#ifndef __NETDEVICE_H__
#define __NETDEVICE_H__

#include <pcap/pcap.h>
#include <stdlib.h>

#include "types.h"

#define NETDEVICE_ERROR		 -1
#define NETDEVICE_ERROR_NULL NULL
#define ETH_ADDR_LEN		 6

/**
 * Script for allocate an eth address
 */
#define ETH_ALLOC(addr) byte *addr = (byte *)calloc(ETH_ADDR_LEN, sizeof(byte))

typedef struct netdevice netdevice_t;
typedef struct protocol protocol_t;
typedef void (*netdevice_handler)(netdevice_t *netdevice, const byte packet, unsigned int length);

struct netdevice {
	pcap_t *capture_handle;	  // Pcap capture handle
	protocol_t *proto_list;	  // Head of rotocol list
};							  // Resources of netdevice

struct protocol {
	two_bytes eth_type;			  // Protocol's ethertype
	netdevice_handler callback;	  // Callback functoin
	netdevice_t *netdevice;		  // Protocol's netdevice
	protocol_t *next;			  // Next node
};								  // Protocol list map ethertype to callback function

/*=================
 * Protocol Format
 *=================*/
typedef struct {
	byte eth_dst[ETH_ADDR_LEN];	  // Destination MAC address
	byte eth_src[ETH_ADDR_LEN];	  // Source MAC address
	two_bytes eth_type;			  // Ethertype
} eth_hdr_t;					  // Ethernet header

extern int netdevice_getdevice(const int dev_sel_no, char *dev_name);

extern byte *string_to_eth_addr(char *eth_addr_str);

#endif