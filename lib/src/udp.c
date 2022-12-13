#include "udp.h"

#include "ip.h"

void test_udp_callback(const byte *data, const u_int length) {
	// print_data(data, length);
}

netdevice_t *udp_init() {
	ip_add_protocol(IP_PROTO_UDP, test_udp_callback, "UDP");
	return NULL;
}