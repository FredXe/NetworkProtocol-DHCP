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
	// long long int a = 0x3903F326;
	// printf("%s\n", (char *)&a);
	// byte *eth = string_to_eth_addr("20:7b:d2:19:e8:ff");
	// byte *dst_eth = string_to_eth_addr("70:82:69:68:68:89");
	// byte dst_eth[ETH_ADDR_LEN] = "FREDDY";

	// char dev_name[20];
	// char errbuf[PCAP_ERRBUF_SIZE];
	// netdevice_getdevice(0, dev_name);
	// printf("%s\n", dev_name);
	// eth_hdr_t *eth_hdr = (eth_hdr_t *)calloc(1, sizeof(eth_hdr_t));
	// memcpy(eth_hdr->eth_dst, dst_eth, ETH_ADDR_LEN);
	// memcpy(eth_hdr->eth_src, eth, ETH_ADDR_LEN);
	// eth_hdr->eth_type = 0x0608;

	// byte pay[10];
	// netdevice_xmit(device, eth_hdr, pay, 0);
	// netdevice_add_protocol(device, IPV4_ETH_TYPE, callback_test);
	// netdevice_rx(device);
	// printf("%s\n", ip_addr_to_string(ip, NULL));
	// arp_request(device, ip);
	// arp_request(device, ip);
	// arp_request(device, ip);
	// arp_request(device, ip);
	netdevice_t *device = dhcp_init();

	byte ip[IP_ADDR_LEN];
	IP_COPY(ip, string_to_ip_addr("192.168.1.116"));
	dhcp_request(ip);
	// ip_add_protocol(IP_PROTO_UDP, test_udp_callback);

	// byte ip[IP_ADDR_LEN];
	// memcpy(ip, string_to_ip_addr("192.168.1.10"), IP_ADDR_LEN);
	// memcpy(ip, string_to_ip_addr("8.8.8.8"), IP_ADDR_LEN);
	// ipv4_hdr_t ip_header = ip_hdr_maker(IP_PROTO_UDP, get_my_ip(device), ip, 100);
	// byte data[100] = "FREDDY :D:D:D";
	// dhcp_send(data, 100);
	// netdevice_add_protocol(device, ETH_IPV4, callback_test);
	// printf("%d\n", netdevice_chk_proto_list(device, ETH_IPV4));
	// printf("%d\n", netdevice_chk_proto_list(device, ETH_ARP));
	// byte src[IP_ADDR_LEN], dst[IP_ADDR_LEN];
	// IP_COPY(src, string_to_ip_addr("192.168.1.102"));
	// IP_COPY(dst, string_to_ip_addr("192.168.1.255"));
	// udp_pseudo_hdr_t pseudo_hdr = udp_pseudo_hdr_maker(src, dst, 0x3400);
	// printf("sum=%x\n", udp_checksum(pseudo_hdr, data));
	// ip_send(&ip_header, data, 100);
	// arp_send(NULL, ip, ETH_IPV4, (byte *)&ip_header, 20);
	while (netdevice_rx(device) >= 0)
		// ip_send(&ip_header, data, 100);
		;
	netdevice_close(device);
	// free(eth_hdr);
	// free(dst_eth);

	return 0;
}