#ifndef __UDP_H__
#define __UDP_H__

#include "util.h"

#define IP_PROTO_UDP 0x11	// IP protocol number of UDP

void test_udp_callback(const byte *data, const u_int length) {
	print_data(data, length);
}

#endif