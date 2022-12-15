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

int dhcp_send(const byte *data, u_int data_len) {
	byte ip[4];
	IP_COPY(ip, string_to_ip_addr("192.168.1.10"));
	udp_pseudo_hdr_t pseudo_hdr =
		udp_pseudo_hdr_maker(get_my_ip(NULL), ip, swap16(data_len + sizeof(udp_hdr_t)));
	udp_hdr_t udp_hdr =
		udp_hdr_maker(swap16(8888), swap16(8888), swap16(data_len + sizeof(udp_hdr_t)));
	udp_send(pseudo_hdr, udp_hdr, data, data_len);
	return 0;
}

void dhcp_main(const byte *dhcp_msg, u_int msg_len) {
	printf(":D================\n");
}