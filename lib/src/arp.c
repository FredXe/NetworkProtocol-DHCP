#include "arp.h"

#include <string.h>

#include "util.h"

struct {
	ip_addr_t dst_ip_addr;	 // Destination IP address
	two_bytes eth_type;		 // Ethertype
	u_int payload_len;		 // Length of payload
	byte payload[MTU];		 // Payload
} arp_to_send_que;			 // Sending queue of arp_send()

#define MAX_ARPIP_N 8	// The max number of ARP table's elements

typedef struct {
	byte ip_addr[IP_ADDR_LEN];	   // IP address
	byte mac_addr[ETH_ADDR_LEN];   // MAC address
} ip_mac_addr;					   // IP - MAC reference

// ARP table
static ip_mac_addr arp_table[MAX_ARPIP_N];
// The number of the ARP table's element
static int arp_table_n = 0;

static const byte *arp_look_up(const byte *ip_addr);
static void arp_table_add(byte *ip_addr, byte *mac_addr);

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
	arp_t *arp_pkt = (arp_t *)packet;	// ARP packet

#if (DEBUG_ARP == 1)
	arp_dump(arp_pkt);
#endif

	switch (arp_pkt->op) {
	case ARP_OP_REQUEST:
		if (memcmp(arp_pkt->dst_ip_addr, get_my_ip(device), IP_ADDR_LEN) == 0)
			arp_reply(device, arp_pkt->src_eth_addr, arp_pkt->src_ip_addr);
		break;
	case ARP_OP_REPLY:
		// Cache this ARP reply if we haven't
		if (GET_IP(arp_pkt->dst_ip_addr) == GET_IP(get_my_ip(device)) &&
			arp_look_up(arp_pkt->src_ip_addr) == NULL)
			arp_table_add(arp_pkt->src_ip_addr, arp_pkt->src_eth_addr);

		if (arp_to_send_que.payload_len > 0) {
			if (GET_IP(arp_pkt->src_ip_addr) == arp_to_send_que.dst_ip_addr) {
				arp_resend(device);
			}
		}
		break;
	default:
		break;
	}
}

/**
 * Interface for upper layer to send packet
 * to specific IP address
 * @param device Interface to send
 * @param dst_ip_addr Destination IP address
 * @param eth_type Ethertype
 * @param payload Payload
 * @param payload_len Length of payload
 * @return 0 on success,
 * ARP_ERROR on xmit error,
 * ARP_UNKNOWN_MAC on unknow destination
 * MAC address
 */
int arp_send(netdevice_t *device, byte *dst_ip_addr, two_bytes eth_type, byte *payload,
			 u_int payload_len) {
	eth_hdr_t eth_hdr;	 // Ethernet header

	if (arp_look_up(dst_ip_addr) != NULL) {

		// Build up the Ethernet header
		memcpy(eth_hdr.eth_dst, arp_look_up(dst_ip_addr), ETH_ADDR_LEN);
		memcpy(eth_hdr.eth_src, netdevice_get_my_mac(device), ETH_ADDR_LEN);
		eth_hdr.eth_type = eth_type;

		// Send the packet, return ARP_ERROR if netdevice_xmit() on error
		if (netdevice_xmit(device, &eth_hdr, payload, payload_len) == NETDEVICE_ERROR) {
			fprintf(stderr, "%s:%d in %s(): netdevice_xmit(): error\n", __FILE__, __LINE__,
					__func__);
			return ARP_ERROR;
		}
	} else {
		// Store the packet to the to_send_que
		arp_to_send_que.dst_ip_addr = GET_IP(dst_ip_addr);
		arp_to_send_que.eth_type = eth_type;
		arp_to_send_que.payload_len = payload_len;
		memcpy(arp_to_send_que.payload, payload, payload_len);

		arp_request(device, dst_ip_addr);
		return ARP_UNKNOWN_MAC;
	}

#if (DEBUG_ARP == 1)
	printf("arp_send(): Packet sent to %s (%s) eth_type=%04x len=%d\n",
		   ip_addr_to_string(dst_ip_addr, NULL), eth_addr_to_string(eth_hdr.eth_dst, NULL),
		   swap16(eth_type), payload_len);
#endif

	return 0;
}

/**
 * Resend the packet inside arp_to_send_que
 * @param device Interface to send
 */
void arp_resend(netdevice_t *device) {
	arp_send(device, (byte *)&arp_to_send_que.dst_ip_addr, arp_to_send_que.eth_type,
			 arp_to_send_que.payload, arp_to_send_que.payload_len);

	// Reset the to send queue
	memset(arp_to_send_que.payload, 1, arp_to_send_que.payload_len);
	arp_to_send_que.payload_len = 0;
	arp_to_send_que.dst_ip_addr = 0;
	arp_to_send_que.eth_type = 0;
}

/**
 * Look up the ARP table to check if it's inside
 * @param ip_addr IP address use to check
 * @return MAC address of ip_addr,
 * NULL if not found
 */
const byte *arp_look_up(const byte *ip_addr) {
	// Go through ARP table
	for (int i = 0; i <= arp_table_n; i++) {
		// Return if ARP table has it inside
		if (memcmp(ip_addr, arp_table[i].ip_addr, IP_ADDR_LEN) == 0)
			return arp_table[i].mac_addr;
	}
	return NULL;
}

/**
 * Add IP - MAC pair to ARP table
 * @param ip_addr IP address
 * @param mac_addr MAC address
 */
void arp_table_add(byte *ip_addr, byte *mac_addr) {
	arp_table_n = (arp_table_n + 1) % MAX_ARPIP_N;
	memcpy(arp_table[arp_table_n].ip_addr, ip_addr, IP_ADDR_LEN);
	memcpy(arp_table[arp_table_n].mac_addr, mac_addr, ETH_ADDR_LEN);

#if (DEBUG_ARP_CACHE == 1)
	char ip_buf[IP_BUF_LEN], mac_buf[MAC_BUF_LEN];

	printf("ARP cached #%d: %s - %s\n", arp_table_n, ip_addr_to_string(ip_addr, ip_buf),
		   ip_addr_to_string(mac_addr, mac_buf));
#endif
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

/**
 * Print ARP packet in format
 * @param arp ARP packet
 */
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
	return;
}
