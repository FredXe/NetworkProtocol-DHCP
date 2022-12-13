#include "ip.h"

#include "arp.h"
#include "util.h"

static ip_protocol_t *ip_proto_list = NULL;

static ipv4_info_t ipv4_info;	// IPv4 information

static two_bytes ip_checksum(const ipv4_hdr_t header_in);

/**
 * Initialize IP by initialize ARP and regist
 * IPv4 to netdevice
 * @return netdevice_t* Interface,
 * IP_ERROR_NULL if error.
 */
netdevice_t *ip_init() {
	// Initialize ARP and get device
	netdevice_t *device = arp_init();

	// Get my IPv4 information
	get_my_ip_info(&ipv4_info);

	// Regist IPv4 to netdevice protocol list
	if (netdevice_add_protocol(device, ETH_IPV4, ip_main) != 0) {
		fprintf(stderr, ERR_COLOR "%s:%d in %s(): netdevice_add_protocol() error\n" NONE, __FILE__,
				__LINE__, __func__);
		return IP_ERROR_NULL;
	}

	return device;
}

/**
 * Search IP protocol list and return the
 * specific protocol name
 * @param protocol IP protocol number to search
 * @param buf Protocol name buf, set NULL to
 * use default static buf
 * @return Protocol name,
 * "Unknown" if protocol not found
 */
const char *ip_proto_to_string(const byte protocol, char *buf) {
	ip_protocol_t *ip_it = ip_proto_list;
	static char proto_buf[PROTO_NAME_LEN];
	if (buf == NULL)
		buf = proto_buf;
	while (ip_it != NULL) {
		if (ip_it->protocol == protocol) {
			strcpy(buf, ip_it->name);
			return buf;
		}
		ip_it = ip_it->next;
	}
	return "Unknown";
}

/**
 * Check if the IP address is in the same subnet
 * @param ip IP address to check
 * @return 1 if yes, 0 if no
 */
int is_my_subnet(const byte *ip) {
	ip_addr_t ip_in = GET_IP(ip);
	ip_addr_t subnet = GET_IP(ipv4_info.subnet);
	return ((ip_in & subnet) == subnet);
}

/**
 * IPv4 header builder with only parameter
 * most used.
 * @param protocol Upper layer protocol
 * @param src_ip Source IP address
 * @param dst_ip Destination IP address
 * @param data_len Length of data
 * @return Header built
 */
const ipv4_hdr_t ip_hdr_maker(const byte protocol, const byte *src_ip, const byte *dst_ip,
							  const u_int data_len) {
	ipv4_hdr_t header;					  // IPv4 header that returns
	int hdr_len = sizeof(ipv4_hdr_t);	  // Length of header
	int total_len = hdr_len + data_len;	  // Total length

	// Build up the header
	header.ver_hlen = VER_HLEN(IP_VERSION, IP_MIN_HLEN);
	header.DS_ECN = 0;
	// Swap since Endian
	header.total_len = swap16((two_bytes)total_len);

	header.id = 0;
	header.flag_frgofst = 0;
	header.ttl = IP_MAX_TTL;
	header.protocol = protocol;
	// Compute later
	header.hdr_chksum = 0;

	IP_COPY(header.src_ip, src_ip);
	IP_COPY(header.dst_ip, dst_ip);

	// Fill back checksum
	header.hdr_chksum = ip_checksum(header);

	return header;
}

/**
 * API for upper layer to send packet through IPv4
 * @param ip_hdr IPv4 header
 * @param data Data from upper layer
 * @param data_len Length of data
 * @return 0 on success,
 * IP_ERROR if failed arp_send()
 */
int ip_send(const ipv4_hdr_t *ip_hdr, const byte *data, const u_int data_len) {
	byte payload[MTU];				  // Payload to send
	int hdr_len = HLEN(ip_hdr) * 4;	  // Length of header

	// Build the payload
	memcpy(payload, ip_hdr, hdr_len);
	memcpy(payload + hdr_len, data, data_len);

	// Send to default gateway if destination IP is not in the same subnet
	const byte *arp_dst_ip = is_my_subnet(ip_hdr->dst_ip) ? ip_hdr->dst_ip : ipv4_info.gateway_d;
	int payload_len = hdr_len + data_len;

#if (DEBUG_IP_SEND == 1)
	char dst[IP_BUF_LEN];
	printf(IP_2_DEBUG_COLOR "IP send" NONE " to " IP_DEBUG_COLOR "%s" NONE " (" IP_DEBUG_COLOR
							"proto=%s len=%d" NONE ") \n",
		   ip_addr_to_string(ip_hdr->dst_ip, dst), ip_proto_to_string(ip_hdr->protocol, NULL),
		   payload_len);
#endif

	// Send by calling arp_send(), return IP_ERROR if failed
	if (arp_send(NULL, arp_dst_ip, ETH_IPV4, payload, payload_len) == ARP_ERROR) {
		fprintf(stderr, ERR_COLOR "%s:%d in %s(): arp_send(): error\n" NONE, __FILE__, __LINE__,
				__func__);
		return IP_ERROR;
	}

	return 0;
}

/**
 * IPv4 capture handle while received packet,
 * than pass it to upper layer by callback
 * function in IP protocol list
 * @param device Device pass from netdevice
 * @param packet Ethernet payload
 * @param length Length of packet
 */
void ip_main(netdevice_t *device, const byte *packet, const u_int packet_len) {
	if (packet_len < (IP_MIN_HLEN * 4)) {
		fprintf(stderr, ERR_COLOR "%s:%d in %s(): IPv4 packet only have header\n" NONE, __FILE__,
				__LINE__, __func__);
		return;
	}

	ipv4_hdr_t *header = (ipv4_hdr_t *)packet;

	int data_len = packet_len - sizeof(ipv4_hdr_t);	  // Length of data
	byte data[MTU];									  // Data of packet
	memcpy(data, packet + sizeof(ipv4_hdr_t), packet_len);

#if (DEBUG_IP_RECEIVED == 1)
	char src[IP_BUF_LEN], dst[IP_BUF_LEN];
	printf(IP_2_DEBUG_COLOR "IP received" NONE ": " IP_DEBUG_COLOR "%s" NONE " => " IP_DEBUG_COLOR
							"%s\n" NONE,
		   ip_addr_to_string(header->src_ip, src), ip_addr_to_string(header->dst_ip, dst));
#endif

	ip_protocol_t *ip_it = ip_proto_list;
	while (ip_it != NULL) {
		if (ip_it->protocol == header->protocol) {
			ip_it->callback(data, data_len);
			break;
		}
		ip_it = ip_it->next;
	}
	return;
}

/**
 * Check if the protocol is inside the
 * IP protocol list
 * @param protocol Key
 * @return 1 on found,
 * 0 on not found
 */
int ip_chk_proto_list(const byte protocol) {
	ip_protocol_t *ip_it = ip_proto_list;	// Iterator of IP protocol list

	// Go through the IP protocol list
	while (ip_it != NULL) {
		if (ip_it->protocol == protocol)
			return 1;
		ip_it = ip_it->next;
	}
	return 0;
}

/**
 * API for upper layer to regist IP
 * protocol and it's callback function
 * @param protocol IP protocol number
 * @param callback Callback function of
 * upper layer
 * @return 0 on success,
 * IP_ERROR if failed
 */
int ip_add_protocol(const byte protocol, const ip_handler callback, const char *name) {
	if (ip_chk_proto_list(protocol) == 1) {
		fprintf(stderr, ERR_COLOR "%s:%d in %s(): protocol is inside the list\n" NONE, __FILE__,
				__LINE__, __func__);
		return IP_ERROR;
	}

	// New protocol
	ip_protocol_t *new_proto = (ip_protocol_t *)calloc(1, sizeof(ip_protocol_t));

	// Set the protocol
	new_proto->protocol = protocol;
	new_proto->callback = callback;
	strcpy(new_proto->name, name);

	// Insert it into the list head
	new_proto->next = ip_proto_list;
	ip_proto_list = new_proto;

	return 0;
}

/**
 * Free the resources of IP protocol list
 */
void ip_close() {
	// Iterator of IP protocol list
	ip_protocol_t *ip_it = ip_proto_list;
	// Pointer that will free
	ip_protocol_t *ip_free = ip_it;

	// Go through the list and free the elements
	while (ip_it != NULL) {
		ip_it = ip_it->next;
		free(ip_free);
		ip_free = ip_it;
	}

	// Set IP protocol list to NULL
	ip_proto_list = NULL;

	return;
}

/**
 * Checksum for IPv4 header
 * @param header_in Header to checksum
 * @return Checksum result
 */
two_bytes ip_checksum(const ipv4_hdr_t header_in) {
	ipv4_hdr_t header = header_in;	 // Copy of header input

	// Set header checksum
	header.hdr_chksum = 0;
	two_bytes new_chksum;
	new_chksum = checksum((byte *)&header, HLEN(&header) * 4);

	return new_chksum;
}