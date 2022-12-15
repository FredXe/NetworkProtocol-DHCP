#include "udp.h"

#include "ip.h"

// Head of UDP protocol list
static udp_protocol_t *udp_proto_list = NULL;

/**
 * UDP check sum method defined in RFC 768
 * @param pseudo_hdr A pseudo header to checksum
 * @param udp_hdr UDP header
 * @param udp_data UDP data
 * @return Checksum result
 */
two_bytes udp_checksum(udp_pseudo_hdr_t pseudo_hdr, udp_hdr_t udp_hdr, const byte *udp_data) {
	// Length of UDP datagram
	int udp_dtgrm_len = swap16(udp_hdr.length);
	int checksum_len = sizeof(udp_pseudo_hdr_t) + udp_dtgrm_len;

	// Set the old checksum into 0
	udp_hdr.checksum = 0;

	// Checksum data buffer
	byte buf[checksum_len];

	/**
	 * Fill up the buf with those two header
	 * and UDP data
	 */
	// Fill the pseudo header
	memcpy(buf, &pseudo_hdr, sizeof(udp_pseudo_hdr_t));

	// Buffer pointer's offset
	int offset = sizeof(udp_pseudo_hdr_t);
	// Fill the UDP header
	memcpy(buf + offset, &udp_hdr, sizeof(udp_hdr_t));

	offset += sizeof(udp_hdr_t);
	// Length of UDP data
	int udp_data_len = udp_dtgrm_len - sizeof(udp_hdr_t);
	// Fill the UDP data
	memcpy(buf + offset, udp_data, udp_data_len);

	// Checksum and return it
	return checksum(buf, checksum_len);
}

/**
 * Build a UDP pseudo header with specify parameter
 * @param src_ip Source IP address
 * @param dst_ip Destination IP address
 * @param udp_len Length of UDP datagram
 * in Big Endian (Network transmit type)
 * @return UDP pseudo header
 */
udp_pseudo_hdr_t udp_pseudo_hdr_maker(const byte *src_ip, const byte *dst_ip, two_bytes udp_len) {
	udp_pseudo_hdr_t pseudo_hdr;   // UDP pseudo header that returns

	// Fill up the contents
	IP_COPY(pseudo_hdr.src_ip, src_ip);
	IP_COPY(pseudo_hdr.dst_ip, dst_ip);
	pseudo_hdr.zeros = 0x00;
	pseudo_hdr.IP_proto = IP_PROTO_UDP;
	pseudo_hdr.udp_len = udp_len;

	return pseudo_hdr;
}

/**
 * Build a UDP header with specify parameter.
 * NOTE that all of the parameters is in
 * Big Endian!!
 * @param src_port Source port in Big Endian
 * (Network transmit type)
 * @param dst_port Destination port in Big Endian
 * (Network transmit type)
 * @param length Total length in Big Endian
 * (Network transmit type)
 * @return UDP header
 */
udp_hdr_t udp_hdr_maker(two_bytes src_port, two_bytes dst_port, two_bytes length) {
	udp_hdr_t header;	// UDP header that returns

	// Fill up the elements
	header.src_port = src_port;
	header.dst_port = dst_port;
	header.length = length;
	header.checksum = 0;

	return header;
}

/**
 * Search if the protocol is inside the UDP
 * protocol list, than return it's pointer
 * @param port Port number in Big Endian
 * (Network transmit type)
 * @return udp_protocol_t* specific
 * protocol, NULL if not found
 */
const udp_protocol_t *udp_search_proto(two_bytes port) {
	// Iterator of UDP protocol list
	udp_protocol_t *udp_it = udp_proto_list;

	// Go through the list
	while (udp_it != NULL) {
		// Return 1 if the port matches
		if (udp_it->port == port) {
			return udp_it;
		}
		udp_it = udp_it->next;
	}

	return NULL;
}

/**
 * API for upper layer to regist UDP applicaiton
 * port and it's callback function
 * @param port Port number in Big Endian
 * (Network transmit type)
 * @param callback Callback function of
 * upper layer
 * @param service_name Service name
 * @return 0 on success,
 * UDP_ERROR if it's inside the list
 */
int udp_add_protocol(two_bytes port, const udp_handler callback, const char *service_name) {
	if (udp_search_proto(port) != NULL) {
		fprintf(stderr, ERR_COLOR "%s:%d in %s(): protocol is inside the list\n" NONE, __FILE__,
				__LINE__, __func__);
		return UDP_ERROR;
	}

	// New protocol
	udp_protocol_t *new_proto = calloc(1, sizeof(udp_protocol_t));

	// Fill up the new protocol's elements
	new_proto->port = port;
	new_proto->callback = callback;
	strcpy(new_proto->service_name, service_name);

	new_proto->next = udp_proto_list;
	udp_proto_list = new_proto;

#if (DEBUG_UDP_ADD_PROTO == 1)
	printf(UDP_2_DEBUG_COLOR "UDP add protocol" NONE ": " UDP_DEBUG_COLOR "port=%d, name=%s" NONE
							 "\n",
		   swap16(port), service_name);
#endif

	return 0;
}

/**
 * API for upper layer to send packet through UDP
 * @param udp_param UDP parameters
 * @param data Data to send
 * @param data_len Length of data
 * @return 0 on success,
 * UDP_ERROR if ip_send() failed
 */
int udp_send(udp_param_t udp_param, const byte *data, u_int data_len) {
	// Total length of UDP datagram
	u_int udp_dtgrm_len = data_len + sizeof(udp_hdr_t);
	udp_pseudo_hdr_t pseudo_hdr =
		udp_pseudo_hdr_maker(udp_param.src_ip, udp_param.dst_ip, swap16(udp_dtgrm_len));
	udp_hdr_t udp_hdr =
		udp_hdr_maker(udp_param.src_port, udp_param.dst_port, swap16(udp_dtgrm_len));

	/**
	 *  Build the IPv4 header
	 */

	// Pointer of source and destination IP address
	byte *src_ip = pseudo_hdr.src_ip;
	byte *dst_ip = pseudo_hdr.dst_ip;
	// IPv4 header to send
	ipv4_hdr_t ip_header = ip_hdr_maker(IP_PROTO_UDP, src_ip, dst_ip, udp_dtgrm_len);

	/**
	 * Build the UDP datagram
	 */
	// Compute the checksum
	udp_hdr.checksum = udp_checksum(pseudo_hdr, udp_hdr, data);

	// Data buffer to send to IP
	byte buf[udp_dtgrm_len];

	// Fill up the buffer
	memcpy(buf, &udp_hdr, sizeof(udp_hdr_t));
	memcpy(buf + sizeof(udp_hdr_t), data, data_len);

	// Send out, return UDP_ERROR if failed
	if (ip_send(ip_header, buf, udp_dtgrm_len) == IP_ERROR) {
		fprintf(stderr, ERR_COLOR "%s:%d in %s(): ip_send() error\n" NONE, __FILE__, __LINE__,
				__func__);
		return UDP_ERROR;
	}

#if (DEBUG_UDP_SEND == 1)
	char src_buf[IP_BUF_LEN], dst_buf[IP_BUF_LEN];
	const udp_protocol_t *protocol;
	char service_name[SERVICE_NAME_LEN];

	if ((protocol = udp_search_proto(udp_hdr.dst_port)) != NULL)
		strcpy(service_name, protocol->service_name);
	else
		strcpy(service_name, "Unknown");

	printf(UDP_2_DEBUG_COLOR
		   "UDP Send  " NONE "(" UDP_DEBUG_COLOR "proto=%s len=%d" NONE ")\n"
		   "\tFrom " IP_DEBUG_COLOR "%-16s" NONE ":" UDP_DEBUG_COLOR "%d" NONE "\n"
		   "\tTo   " IP_DEBUG_COLOR "%-16s" NONE ":" UDP_DEBUG_COLOR "%d" NONE "\n",
		   service_name, swap16(udp_hdr.length), ip_addr_to_string(src_ip, src_buf),
		   swap16(udp_hdr.src_port), ip_addr_to_string(dst_ip, dst_buf), swap16(udp_hdr.dst_port));
#endif

	return 0;
}

/**
 * UDP capture handle for receive data from
 * lower layer, pass it to upper layer using
 * the callback function in the UDP protocol
 * list
 * @param udp_datagram UDP datagram
 * @param datagram_len Length of UDP datagram
 */
void udp_main(const byte *udp_datagram, const u_int datagram_len) {
	udp_hdr_t *udp_hdr = (udp_hdr_t *)udp_datagram;

	// Upper layer's protocol
	const udp_protocol_t *proto = udp_search_proto(udp_hdr->dst_port);

	// Return if the protocol is unknown
	if (proto == NULL)
		return;

	// Length of datagram
	int data_len = datagram_len - sizeof(udp_hdr_t);
	// Data buffer pass to upper layer
	byte udp_data[data_len];
	memcpy(udp_data, udp_datagram + sizeof(udp_hdr_t), data_len);

	// Pass the data to the upper layer
	proto->callback(udp_data, data_len);

	return;
}

/**
 * Initialize the UDP's resources and
 * regist UDP to lower layer (aka IP)
 * @return netdevice_t* Interface
 * UDP_ERROR_NULL if ip_init() error
 */
netdevice_t *udp_init() {
	netdevice_t *device;

	// Return UDP_ERROR_NULL if ip_init() error
	if ((device = ip_init()) == IP_ERROR_NULL) {
		fprintf(stderr, ERR_COLOR "%s:%d in %s(): ip_init() error\n" NONE, __FILE__, __LINE__,
				__func__);
		return UDP_ERROR_NULL;
	}

	// Regist UDP to IP
	ip_add_protocol(IP_PROTO_UDP, udp_main, "UDP");

	return device;
}