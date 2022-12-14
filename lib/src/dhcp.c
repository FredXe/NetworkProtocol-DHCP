#include "dhcp.h"

#include "udp.h"

netdevice_t *dhcp_init() {
	netdevice_t *device;

	// Return DHCP_ERROR_NULL if udp_init() error
	if ((device = udp_init()) == UDP_ERROR_NULL) {
		fprintf(stderr, ERR_COLOR "%s:%d in %s(): udp_init() error\n" NONE, __FILE__, __LINE__,
				__func__);
		return DHCP_ERROR_NULL;
	}

	udp_add_protocol(UDP_PORT_DHCP_S, dhcp_main, "DHCP");

	return device;
}

void dhcp_main(const byte *dhcp_msg, u_int msg_len) {
	printf(":D================\n");
}