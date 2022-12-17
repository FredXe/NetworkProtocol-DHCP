/**
 * test.c
 * Program to test something
 * >_ 'make runtest'
 */

#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>

#include "arp.h"
#include "dhcp.h"
#include "ip.h"
#include "netdevice.h"
#include "types.h"
#include "udp.h"
#include "util.h"

int i = 0;
void callback_test(netdevice_t *netdevice, const byte *packet, unsigned int length) {
	printf("%d\n", i);
	i++;

	return;
}

int main() {
	netdevice_t *device = dhcp_init();

	byte ip[IP_ADDR_LEN];
	IP_COPY(ip, string_to_ip_addr("192.168.1.116"));

	while (netdevice_rx(device) >= 0)
		dhcp_discover(MY_MAC_ADDR);
	// ;
	netdevice_close(device);

	return 0;
}