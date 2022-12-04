#include "ip.h"
#include "netdevice.h"
#include "util.h"

#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>

int main() {
	char eth_str[20] = "ff:7b:d2:19:e8:69";
	char ip_str[20] = "192.168.1.1";

	u_int8_t *eth = string_to_eth_addr(eth_str);
	u_int8_t *ip = string_to_ip_addr(ip_str);

	// for (int i = 0; i < ETH_ADDR_LEN; i++) {
	// 	printf("%" PRIu8 ":", eth[i]);
	// }
	printf("\n");
	free(eth);
	free(ip);

	return 0;
}