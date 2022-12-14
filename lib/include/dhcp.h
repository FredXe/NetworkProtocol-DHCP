#ifndef __DHCP_H__
#define __DHCP_H__

#include "netdevice.h"

#define UDP_PORT_DHCP_S 0x4300	 // DHCP port on server
#define UDP_PORT_DHCP_C 0x4400	 // DHCP port on client

#define DHCP_ERROR		-1
#define DHCP_ERROR_NULL NULL

/*=================
 * Protocol Format
 *=================*/

/*================
 * Public Methods
 *================*/
extern netdevice_t *dhcp_init();
extern int dhcp_send(const byte *data, u_int data_len);
extern void dhcp_main(const byte *dhcp_msg, u_int msg_len);

#endif