#ifndef __UDP_H__
#define __UDP_H__

#include "netdevice.h"
#include "util.h"

#define IP_PROTO_UDP 0x11	// IP protocol number of UDP

extern void test_udp_callback(const byte *data, const u_int length);
extern netdevice_t *udp_init();

#endif