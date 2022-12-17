#ifndef __UDP_H__
#define __UDP_H__

#include "netdevice.h"
#include "util.h"

#define IP_PROTO_UDP 0x11	// IP protocol number of UDP

#define UDP_ERROR	   -1	  // UDP common error
#define UDP_ERROR_NULL NULL	  // UDP common error with NULL

typedef void (*udp_handler)(const byte *data, u_int data_len);

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

typedef struct {
	byte src_ip[IP_ADDR_LEN];	// Source IP address
	two_bytes src_port;			// Source port
	byte dst_ip[IP_ADDR_LEN];	// Destination IP address
	two_bytes dst_port;			// Destination port
} udp_param_t;

#define SERVICE_NAME_LEN 64
typedef struct udp_protocol udp_protocol_t;

struct udp_protocol {
	two_bytes port;						   // Port the service use
	udp_handler callback;				   // Callback function of upper layer
	char service_name[SERVICE_NAME_LEN];   // Service name
	udp_protocol_t *next;				   // Next protocol
};										   // Application layer protocol information

/*================
 * Public Methods
 *================*/
extern two_bytes udp_checksum(udp_pseudo_hdr_t pseudo_hdr, udp_hdr_t udp_hdr, const byte *udp_data);
extern udp_pseudo_hdr_t udp_pseudo_hdr_maker(const byte *src_ip, const byte *dst_ip,
											 two_bytes udp_len);
extern udp_hdr_t udp_hdr_maker(two_bytes src_port, two_bytes dst_port, two_bytes length);
extern const udp_protocol_t *udp_search_proto(two_bytes port);
extern int udp_add_protocol(two_bytes port, const udp_handler callback, const char *service_name);
extern int udp_send(udp_param_t udp_param, const byte *data, u_int data_len);
extern void udp_main(const byte *udp_datagram, u_int datagram_len);
extern netdevice_t *udp_init();

#endif