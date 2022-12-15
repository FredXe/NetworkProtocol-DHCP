#ifndef __DHCP_H__
#define __DHCP_H__

#include "ip.h"
#include "netdevice.h"

#define UDP_PORT_DHCP_S 0x4300	 // DHCP port on server
#define UDP_PORT_DHCP_C 0x4400	 // DHCP port on client

#define DHCP_ERROR		-1
#define DHCP_ERROR_NULL NULL

/*=================
 * Protocol Format
 *=================*/
#define DHCP_XID_LEN	  4
#define DHCP_HDR_ADDR_LEN 16
#define DHCP_SNAME_LEN	  64
#define DHCP_FILE_LEN	  128
#define DHCP_OP_TO_SERVER 0x01
#define DHCP_OP_TO_CLIENT 0x02
#define DHCP_MAGIC_LEN	  4

typedef struct {
	byte op;				  // Operation code
	byte hdr_type;			  // Hardware type
	byte hdr_len;			  // Length of hardware address
	byte hops;				  // Number of router hops
	byte xid[DHCP_XID_LEN];	  // Transaction ID
	two_bytes secs;			  // Senconds from client request has passed
	two_bytes flags;		  // 0x8000 when server broadcasts

	// Note this isn't the same as information of DHCP Offer
	byte ciaddr[IP_ADDR_LEN];		  // Client IP address
	byte yiaddr[IP_ADDR_LEN];		  // Your IP address
	byte siaddr[IP_ADDR_LEN];		  // Server IP address
	byte giaddr[IP_ADDR_LEN];		  // Gateway IP address
	byte chaddr[DHCP_HDR_ADDR_LEN];	  // Client hardware address

	byte sname[DHCP_SNAME_LEN];	  // Server name
	byte file[DHCP_FILE_LEN];	  // Program name of bootstrape
} dhcp_hdr_t;

/*================
 * Public Methods
 *================*/
extern netdevice_t *dhcp_init();
extern void dhcp_discover();
extern void dhcp_request();
extern int dhcp_send(const byte *data, u_int data_len);
extern void dhcp_main(const byte *dhcp_msg, u_int msg_len);

#endif