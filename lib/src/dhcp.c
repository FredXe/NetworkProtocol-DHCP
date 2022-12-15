#include "dhcp.h"

#include <time.h>

#include "dhcp_op.h"
#include "udp.h"

const byte DHCP_MAGIC_COOKIE[DHCP_MAGIC_LEN] = {0x63, 0x82, 0x53, 0x63};

static netdevice_t *device;

static dhcp_op_t *dhcp_op_list = NULL;

static u_int xid_waiting;

/**
 * DHCP option content filler
 * @param ptr Where you wanna fill the option in
 * @param op_tag DHCP option tag
 * @param len_mul Length Multiplier.
 * Numbers of content you wanna fill in
 * @param content The option data
 * @return Total length of the option
 */
static int dhcp_op_filler(byte *ptr, byte op_tag, u_int len_mul, const byte *content) {
	// Let len_mul = 1 if it's Length is a constant
	len_mul = (dhcp_op_list[op_tag].len_mul == 0) ? 1 : len_mul;

	// Length of content
	byte length = dhcp_op_list[op_tag].length * len_mul;

	// Fill the option tag
	memcpy(ptr, &op_tag, 1);

	// Return if the length of the option is 0
	if (dhcp_op_list[op_tag].length == 0)
		return 1;

	// Fill in the length of the content
	memcpy(ptr + 1, &length, 1);

	// Fill in the content
	memcpy(ptr + 2, content, length);

	// Return the content's length + two bytes ahead
	return (length + 2);
}

/**
 * Initialize the DHCP list and regist
 * DHCP into UDP's protocol list
 * @return netdevice_t* Interface,
 * DHCP_ERROR_NULL on error
 */
netdevice_t *dhcp_init() {
	if (device != NULL) {
		fprintf(stderr,
				ERR_COLOR
				"%s:%d in %s(): default netdevice has been initialized, this function should "
				"only be called once\n" NONE,
				__FILE__, __LINE__, __func__);
		return DHCP_ERROR_NULL;
	}

	// Return DHCP_ERROR_NULL if udp_init() error
	if ((device = udp_init()) == UDP_ERROR_NULL) {
		fprintf(stderr, ERR_COLOR "%s:%d in %s(): udp_init() error\n" NONE, __FILE__, __LINE__,
				__func__);
		return DHCP_ERROR_NULL;
	}

	// Regist DHCP to UDP
	if (udp_add_protocol(UDP_PORT_DHCP_C, dhcp_main, "DHCP") == UDP_ERROR) {
		fprintf(stderr, ERR_COLOR "%s:%d in %s(): udp_add_protocol() error\n" NONE, __FILE__,
				__LINE__, __func__);
		return DHCP_ERROR_NULL;
	}

	// Initialize the option list
	dhcp_op_init(&dhcp_op_list);

	srand(time(NULL));

	return device;
}

/**
 * Send a DHCP Discover message
 */
void dhcp_discover() {
	dhcp_hdr_t header;	 // DHCP header to send

	/**
	 * Fill in the data
	 */
	header.op = DHCP_OP_TO_SERVER;
	header.hdr_type = ETH_HDR_TYPE;
	header.hdr_len = ETH_ADDR_LEN;
	header.hops = 0;
	xid_waiting = rand();
	memcpy(header.xid, "FRED", DHCP_XID_LEN);
	// memcpy(header.xid, &xid_waiting, DHCP_XID_LEN);
	header.secs = 0;
	header.flags = 0;

	GET_IP(header.ciaddr) = 0;
	GET_IP(header.yiaddr) = 0;
	GET_IP(header.siaddr) = 0;
	GET_IP(header.giaddr) = 0;
	memcpy(header.chaddr, MY_MAC_ADDR, ETH_ADDR_LEN);

	memset(header.sname, 0, DHCP_SNAME_LEN);
	memset(header.file, 0, DHCP_FILE_LEN);

	// Total length of DHCP discover packet
	int dhcp_discover_len = sizeof(dhcp_hdr_t) + 8;

	// DHCP discove packet buffer
	byte buf[dhcp_discover_len];

	// Fill in the header
	memcpy(buf, &header, sizeof(dhcp_hdr_t));

	// Fill in the DHCP Magic Cookie
	int offset = sizeof(dhcp_hdr_t);   // Offset of the buf
	memcpy(buf + offset, DHCP_MAGIC_COOKIE, 4);

	// Update the offset
	offset += 4;
	// Fill in the Message type
	offset += dhcp_op_filler(buf + offset, DHCP_OP.Message_Type, 1, &DHCP_MSG.DISCOVER);
	// Fill in the End option
	dhcp_op_filler(buf + offset, DHCP_OP.End, 1, NULL);

	// Send out the DHCP discover
	dhcp_send(buf, dhcp_discover_len);

	return;
}

int dhcp_send(const byte *data, u_int data_len) {
	byte src_ip[4];
	IP_COPY(src_ip, string_to_ip_addr("0.0.0.0"));
	byte dst_ip[4];
	IP_COPY(dst_ip, string_to_ip_addr("255.255.255.255"));
	udp_pseudo_hdr_t pseudo_hdr =
		udp_pseudo_hdr_maker(src_ip, dst_ip, swap16(data_len + sizeof(udp_hdr_t)));
	udp_hdr_t udp_hdr =
		udp_hdr_maker(UDP_PORT_DHCP_C, UDP_PORT_DHCP_S, swap16(data_len + sizeof(udp_hdr_t)));
	udp_send(pseudo_hdr, udp_hdr, data, data_len);
	return 0;
}

void dhcp_main(const byte *dhcp_msg, u_int msg_len) {
	printf(":D================\n");
}