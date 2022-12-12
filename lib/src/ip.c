#include "ip.h"

#include "arp.h"
#include "util.h"

static two_bytes ip_checksum(const ipv4_hdr_t header_in);

/**
 * Initialize IP by initialize ARP and regist
 * IPv4 to netdevice
 * @return netdevice_t* Interface
 */
netdevice_t *ip_init() {
	// Initialize ARP and get device
	netdevice_t *device = arp_init();

	// Regist IPv4 to netdevice protocol list
	if (netdevice_add_protocol(device, ETH_IPV4, ip_main) != 0) {
		fprintf(stderr, ERR_COLOR "%s:%d in %s(): netdevice_add_protocol() error\n" NONE, __FILE__,
				__LINE__, __func__);
		return IP_ERROR_NULL;
	}

	return device;
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

void ip_main(netdevice_t *device, const byte *packet, u_int length) {}

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