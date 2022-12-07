#include "arp.h"

#include <string.h>

#include "util.h"

/**
 * Send a ARP request packet to specific IP address
 * @param device Interface to send
 * @param dst_ip_addr Destination IP address we're requesting
 * @return 0 on success, ARP_ERROR on error
 */
int arp_request(netdevice_t *device, byte *dst_ip_addr) {
	eth_hdr_t eth_hdr;	 // Ethernet header for ARP request

	// Build up Ethernet header
	memcpy(eth_hdr.eth_dst, ETH_BROADCAST_ADDR, ETH_ADDR_LEN);
	byte *MY_MAC_ADDR = netdevice_get_my_mac(device);
	memcpy(eth_hdr.eth_src, MY_MAC_ADDR, ETH_ADDR_LEN);
	eth_hdr.eth_type = ETH_ARP;

	arp_t arp_pkt;	 // ARP request packet

	// Build up ARP request packet
	arp_pkt.hdr_type = ARP_ETH_TYPE;
	arp_pkt.proto_type = ETH_IPV4;
	arp_pkt.hdr_addr_len = ETH_ADDR_LEN;
	arp_pkt.ip_addr_len = IP_ADDR_LEN;
	arp_pkt.op = ARP_OP_REQUEST;
	memcpy(arp_pkt.src_eth_addr, MY_MAC_ADDR, ETH_ADDR_LEN);
	byte *MY_IP_ADDR = get_my_ip(device);
	memcpy(arp_pkt.src_ip_addr, MY_IP_ADDR, IP_ADDR_LEN);
	memset(arp_pkt.dst_eth_addr, 0, ETH_ADDR_LEN);
	memcpy(arp_pkt.dst_ip_addr, dst_ip_addr, IP_ADDR_LEN);

	/**
	 * Send the packet, free resources and
	 * return ARP_ERROR if netdevice_xmit() error
	 */
	if (netdevice_xmit(device, &eth_hdr, (byte *)&arp_pkt, sizeof(arp_t)) == NETDEVICE_ERROR) {
		fprintf(stderr, "%s:%d in %s(): netdevice_xmit(): error\n", __FILE__, __LINE__, __func__);
		goto err_out;
	}

#if (DEBUG_ARP_REQUEST == 1)
	printf("ARP request to %s\n", ip_addr_to_string(dst_ip_addr));
#endif

	return 0;

// Label for error exit
err_out:
	return ARP_ERROR;
}