#include "arp.h"

int arp_request(netdevice_t *device, byte *ip_addr) {
	eth_hdr_t eth_hdr;

	arp_t apt;
}