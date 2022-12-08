#include "arp.h"

#include <string.h>

#include "util.h"

static const char *arp_op_to_string(two_bytes op);
static void arp_dump(arp_t *arp);

/**
 * Send a ARP request packet to specific IP address
 * @param device Interface to send
 * @param dst_ip_addr Destination IP address we're requesting
 * @return 0 on success, ARP_ERROR on error
 */
int arp_request(netdevice_t *device, byte *dst_ip_a) {
	eth_hdr_t eth_hdr;	 // Ethernet header for ARP request

	// Build up Ethernet header
	memcpy(eth_hdr.eth_dst, ETH_BROADCAST_ADDR, ETH_ADDR_LEN);
	memcpy(eth_hdr.eth_src, netdevice_get_my_mac(device), ETH_ADDR_LEN);
	eth_hdr.eth_type = ETH_ARP;

	arp_t arp_pkt;	 // ARP request packet

	// Build up ARP request packet
	arp_pkt.hdr_type = ARP_ETH_TYPE;
	arp_pkt.proto_type = ETH_IPV4;
	arp_pkt.hdr_addr_len = ETH_ADDR_LEN;
	arp_pkt.ip_addr_len = IP_ADDR_LEN;
	arp_pkt.op = ARP_OP_REQUEST;
	memcpy(arp_pkt.src_eth_addr, netdevice_get_my_mac(device), ETH_ADDR_LEN);
	memcpy(arp_pkt.src_ip_addr, get_my_ip(device), IP_ADDR_LEN);
	memset(arp_pkt.dst_eth_addr, 0, ETH_ADDR_LEN);
	memcpy(arp_pkt.dst_ip_addr, dst_ip_a, IP_ADDR_LEN);

	/**
	 * Send the packet, free resources and
	 * return ARP_ERROR if netdevice_xmit() error
	 */
	if (netdevice_xmit(device, &eth_hdr, (byte *)&arp_pkt, sizeof(arp_t)) == NETDEVICE_ERROR) {
		fprintf(stderr, "%s:%d in %s(): netdevice_xmit(): error\n", __FILE__, __LINE__, __func__);
		goto err_out;
	}

#if (DEBUG_ARP_REQUEST == 1)
	printf("ARP request to %s\n", ip_addr_to_string(dst_ip_a, NULL));
#endif

	return 0;

// Label for error exit
err_out:
	return ARP_ERROR;
}

/**
 * Reply a ARP request packet to specific IP address
 * @param device Interface to send
 * @param dst_eth_addr Destination MAC address we're replying
 * @param dst_ip_addr Destination IP address we're replying
 * @return 0 on success, ARP_ERROR on error
 */
int arp_reply(netdevice_t *device, byte *dst_eth_addr, byte *dst_ip_addr) {
	eth_hdr_t eth_hdr;	 // Ethernet header

	// Build up Ethernet header
	memcpy(eth_hdr.eth_dst, dst_eth_addr, ETH_ADDR_LEN);
	memcpy(eth_hdr.eth_src, netdevice_get_my_mac(device), ETH_ADDR_LEN);
	eth_hdr.eth_type = ETH_ARP;

	arp_t arp_pkt;	 // ARP request packet

	// Build up ARP request packet
	arp_pkt.hdr_type = ARP_ETH_TYPE;
	arp_pkt.proto_type = ETH_IPV4;
	arp_pkt.hdr_addr_len = ETH_ADDR_LEN;
	arp_pkt.ip_addr_len = IP_ADDR_LEN;
	arp_pkt.op = ARP_OP_REPLY;
	memcpy(arp_pkt.src_eth_addr, netdevice_get_my_mac(device), ETH_ADDR_LEN);
	memcpy(arp_pkt.src_ip_addr, get_my_ip(device), IP_ADDR_LEN);
	memcpy(arp_pkt.dst_eth_addr, dst_eth_addr, ETH_ADDR_LEN);
	memcpy(arp_pkt.dst_ip_addr, dst_ip_addr, IP_ADDR_LEN);

	/**
	 * Send the packet, free resources and
	 * return ARP_ERROR if netdevice_xmit() error
	 */
	if (netdevice_xmit(device, &eth_hdr, (byte *)&arp_pkt, sizeof(arp_t)) == NETDEVICE_ERROR) {
		fprintf(stderr, "%s:%d in %s(): netdevice_xmit(): error\n", __FILE__, __LINE__, __func__);
		goto err_out;
	}

#if (DEBUG_ARP_REPLY == 1)
	printf("ARP reply to %s\n", ip_addr_to_string(dst_ip_addr, NULL));
#endif

	return 0;

// Label for error exit
err_out:
	return ARP_ERROR;
}

/**
 * Capture handle function of ARP that lower layer
 * to callback
 * @param device Interface that send out
 * @param packet ARP protocol packet
 * @param length Length of packet
 */
void arp_main(netdevice_t *device, const byte *packet, u_int length) {
	arp_t *arp_pkt = (arp_t *)packet;

#if (DEBUG_ARP == 1)
	arp_dump(arp_pkt);
#endif

	switch (arp_pkt->op) {
	case ARP_OP_REQUEST:
		if (memcmp(arp_pkt->dst_ip_addr, get_my_ip(device), IP_ADDR_LEN) == 0)
			arp_reply(device, arp_pkt->src_eth_addr, arp_pkt->src_ip_addr);
		break;

	default:
		break;
	}
}

/**
 * Convert ARP operation code into string
 * @param op ARP operation code
 * @return const char*, "Unknown" for excepted type
 */
static const char *arp_op_to_string(two_bytes op) {
	switch (op) {
	case ARP_OP_REQUEST:
		return "Request";
	case ARP_OP_REPLY:
		return "Reply";
	default:
		return "Unknown";
		break;
	}
	return NULL;
}

static void arp_dump(arp_t *arp) {
	char src_eth_str[ETH_BUF_LEN], src_ip_str[IP_BUF_LEN];
	char dst_eth_str[ETH_BUF_LEN], dst_ip_str[IP_BUF_LEN];
	printf("ARP Eth=%04x/%d, IP=%04x/%d, Op=%04x(%s)\n"
		   "\tFrom %s (%s)\n"
		   "\tTo   %s (%s)\n",
		   swap16(arp->hdr_type), arp->hdr_addr_len, swap16(arp->proto_type), arp->ip_addr_len,
		   swap16(arp->op), arp_op_to_string(arp->op),
		   eth_addr_to_string(arp->src_eth_addr, src_eth_str),
		   ip_addr_to_string(arp->src_ip_addr, src_ip_str),
		   eth_addr_to_string(arp->dst_eth_addr, dst_eth_str),
		   ip_addr_to_string(arp->dst_ip_addr, dst_ip_str));
}