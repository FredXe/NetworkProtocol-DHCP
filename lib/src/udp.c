#include "udp.h"

#include "ip.h"

// Head of UDP protocol list
static udp_protocol_t *udp_proto_list = NULL;

/**
 * UDP check sum method defined in RFC 768
 * @param pseudo_hdr A pseudo header to checksum
 * @param udp_data UDP data (header + datagram)
 * @return Checksum result
 */
two_bytes udp_checksum(udp_pseudo_hdr_t pseudo_hdr, const byte *udp_data) {
	// Length of UDP datagram
	int udp_dtgrm_len = swap16(((udp_hdr_t *)udp_data)->length);
	int checksum_len = sizeof(udp_pseudo_hdr_t) + udp_dtgrm_len;

	// Checksum data buffer
	byte buf[checksum_len];

	memcpy(buf, &pseudo_hdr, sizeof(udp_pseudo_hdr_t));
	memcpy(buf + sizeof(udp_pseudo_hdr_t), udp_data, udp_dtgrm_len);

	// UDP header ptr point to UDP header in buf
	udp_hdr_t *udp_hdr = (udp_hdr_t *)(buf + sizeof(udp_pseudo_hdr_t));
	// Set the checksum into 0
	udp_hdr->checksum = 0;

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