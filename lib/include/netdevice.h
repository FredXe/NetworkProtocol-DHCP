#ifndef __NETDEVICE_H__
#define __NETDEVICE_H__

#include <pcap/pcap.h>
#include <stdlib.h>

#include "types.h"

#define NETDEVICE_ERROR		 -1
#define NETDEVICE_ERROR_NULL NULL
#define ETH_ADDR_LEN		 6
#define MTU					 1500
#define MIN_ETH_LEN			 60
#define CAP_TIMEOUT			 100

/**
 * Script for allocate an eth address
 */
#define ETH_ALLOC(addr) byte *addr = (byte *)calloc(ETH_ADDR_LEN, sizeof(byte))

typedef struct netdevice netdevice_t;
typedef struct protocol protocol_t;
typedef void (*netdevice_handler)(netdevice_t *netdevice, const byte *packet, unsigned int length);

// alias for struct pcap_pkthdr
typedef struct pcap_pkthdr pcap_pkthdr_t;

struct netdevice {
	pcap_t *capture_handle;	  // Pcap capture handle
	protocol_t *proto_list;	  // Head of protocol list
	char *device_name;		  // Device name of linked interface
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

/*================
 * Public Methods
 *================*/
extern int netdevice_getdevice(const int dev_sel_no, char *dev_name);
extern netdevice_t *netdevice_open(char *device_name, char *errbuf);
extern int netdevice_add_protocol(netdevice_t *netdevice, const two_bytes eth_type,
								  netdevice_handler callback);
extern int netdevice_xmit(const netdevice_t *device, const eth_hdr_t *eth_hdr, const byte *payload,
						  const u_int payload_len);
extern int netdevice_rx(netdevice_t *netdevice);
extern void netdevice_close(netdevice_t *device);
extern byte *netdevice_get_my_mac(const netdevice_t *device);
extern byte *string_to_eth_addr(const char *eth_addr_str);

#endif