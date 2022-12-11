/**
 * test.c
 * Program to test something
 * >_ 'make runtest'
 */
#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>

#include "arp.h"
#include "ip.h"
#include "netdevice.h"
#include "types.h"
#include "util.h"

int i = 0;
void callback_test(netdevice_t *netdevice, const byte *packet, unsigned int length) {
	printf("%d\n", i);
	i++;

	return;
}

int main() {
	// byte *eth = string_to_eth_addr("20:7b:d2:19:e8:ff");
	// byte *dst_eth = string_to_eth_addr("70:82:69:68:68:89");
	// byte dst_eth[ETH_ADDR_LEN] = "FREDDY";

	// char dev_name[20];
	// char errbuf[PCAP_ERRBUF_SIZE];
	// netdevice_init(ETH_TYPE_NULL, NULL);
	eth_hdr_t *eth_hdr = (eth_hdr_t *)calloc(1, sizeof(eth_hdr_t));
	// byte buf[100] = "\x45\x00\x00\x28\x94\x46\x40\x00\x40\x06\x8d\xa2\xc0\xa8\x01\x74"
	// 				"\x2f\xf6\x26\xd5";
	// ipv4_hdr_t ip_hdr;
	// memcpy(&ip_hdr, buf, 20);
	// print_data((byte *)&ip_hdr, 20);
	// print_data((byte *)&ip_hdr.hdr_chksum, 2);
	// ip_hdr.hdr_chksum = 0;
	// two_bytes bufchksum = check_sum((byte *)&ip_hdr, 20);
	// print_data((byte *)&bufchksum, 2);

	byte ip[IP_ADDR_LEN];
	memcpy(ip, string_to_ip_addr("192.168.1.10"), IP_ADDR_LEN);
	byte payload[86] = "FREDDY";
	netdevice_add_protocol(ETH_ARP, arp_main);
	// netdevice_rx(device);
	// byte ip[IP_ADDR_LEN];
	// memcpy(ip, string_to_ip_addr("192.168.1.1"), IP_ADDR_LEN);
	// printf("%s\n", ip_addr_to_string(ip, NULL));
	// arp_request(device, ip);
	// arp_request(device, ip);
	// arp_request(device, ip);
	// arp_request(device, ip);
	arp_send(ip, ETH_IPV4, payload, 86);
	while (netdevice_rx(NULL) >= 0)
		;
	free(eth_hdr);
	// free(dst_eth);

	return 0;
}