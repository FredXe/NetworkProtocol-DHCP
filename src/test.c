/**
 * @file test.c
 * Program to test something
 * to >_ 'make runtest'
 */

#include "ip.h"
#include "netdevice.h"
#include "util.h"

#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>

int main() {
	char eth_str[20] = "ff:7b:d2:19:e8:69";
	char ip_str[20] = "192.168.1.1";

	byte *eth = string_to_eth_addr(eth_str);
	byte *ip = string_to_ip_addr(ip_str);

	char dev_name[20];
	char errbuf[PCAP_ERRBUF_SIZE];
	netdevice_getdevice(1, dev_name);
	printf("%s\n", dev_name);
	netdevice_t *device;
	device = netdevice_open(dev_name, errbuf);

	// device->capture_handle;
	// for (int i = 0; i < ETH_ADDR_LEN; i++) {
	// 	printf("%" PRIu8 ":", eth[i]);
	// }
	// free(dev_name);
	netdevice_close(device);
	free(eth);
	free(ip);

	return 0;
}