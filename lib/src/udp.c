#include "udp.h"

#include "ip.h"

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
 * in Big Endian (Network type)
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

void test_udp_callback(const byte *data, const u_int length) {
	// print_data(data, length);
}

netdevice_t *udp_init() {
	ip_add_protocol(IP_PROTO_UDP, test_udp_callback, "UDP");
	return NULL;
}