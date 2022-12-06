/**
 * test.c
 * Program to test something
 * >_ 'make runtest'
 */

#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>

#include "ip.h"
#include "netdevice.h"
#include "util.h"

int main() {
	byte *eth = string_to_eth_addr("20:7b:d2:19:e8:00");
	// byte *dst_eth = string_to_eth_addr("70:82:69:68:68:89");
	byte dst_eth[ETH_ADDR_LEN] = "FREDDY";
	byte *ip = string_to_ip_addr("192.168.1.1");

	char dev_name[20];
	char errbuf[PCAP_ERRBUF_SIZE];
	netdevice_getdevice(2, dev_name);
	printf("%s\n", dev_name);
	netdevice_t *device;
	device = netdevice_open(dev_name, errbuf);
	eth_hdr_t *eth_hdr = (eth_hdr_t *)calloc(1, sizeof(eth_hdr_t));
	memcpy(eth_hdr->eth_dst, dst_eth, ETH_ADDR_LEN);
	memcpy(eth_hdr->eth_src, eth, ETH_ADDR_LEN);
	eth_hdr->eth_type = 0x0608;
	byte pay[10];
	netdevice_xmit(device, eth_hdr, pay, 0);
	for (int i = 0; i < ETH_ADDR_LEN; i++) {
		printf("%x:", eth_hdr->eth_dst[i]);
	}
	printf("\n");
	for (int i = 0; i < ETH_ADDR_LEN; i++) {
		printf("%" PRIu8 ":", eth_hdr->eth_src[i]);
	}
	netdevice_close(device);
	free(eth_hdr);
	// free(dst_eth);
	free(eth);
	free(ip);

	return 0;
}