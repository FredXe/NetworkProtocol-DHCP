#include "ip.h"

#include "arp.h"
#include "util.h"

static two_bytes ip_checksum(const ipv4_hdr_t *header_in);

netdevice_t *ip_init() {
	netdevice_t *device = arp_init();

	if (netdevice_add_protocol(device, ETH_IPV4, ip_main) != 0) {
		fprintf(stderr, ERR_COLOR "%s:%d in %s(): netdevice_add_protocol() error\n" NONE, __FILE__,
				__LINE__, __func__);
		return IP_ERROR_NULL;
	}

	return device;
}

ipv4_hdr_t ip_hdr_maker(const byte protocol, const ip_addr_t src_ip, const ip_addr_t dst_ip,
						const u_int data_len) {
	ipv4_hdr_t header;
	int hdr_len = sizeof(ipv4_hdr_t);	  // Length of header
	int total_len = hdr_len + data_len;	  // Total length

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

	header.src_ip = src_ip;
	header.dst_ip = dst_ip;

	header.hdr_chksum = ip_checksum(&header);

	return header;
}

void ip_main(netdevice_t *device, const byte *packet, u_int length) {}

two_bytes ip_checksum(const ipv4_hdr_t *header_in) {
	ipv4_hdr_t header = *header_in;	  // Copy of header input

	// Set header checksum
	header.hdr_chksum = 0;
	two_bytes new_chksum;
	new_chksum = checksum((byte *)&header, HLEN(&header) * 4);

	return new_chksum;
}