#include "dhcp.h"

#include <time.h>

#include "dhcp_op.h"

// DHCP Magic Cookie
const byte DHCP_MAGIC_COOKIE[DHCP_MAGIC_LEN] = {0x63, 0x82, 0x53, 0x63};

static dhcp_op_t *dhcp_op_list = NULL;	 // DHCP Options list

static struct {
	// XID that we're waiting server for response
	byte xid_waiting[DHCP_XID_LEN];
} dhcp_req_que;	  // DHCP Request queue

#if (DEBUG_DHCP_HEADER == 1)
/**
 * To print out the DHCP message's header
 * @param header DHCP header
 */
static void dhcp_dump(dhcp_hdr_t header) {
	printf("\t|==========" DHCP_DEBUG_COLOR "HEADER" NONE "===========|\n");
	printf("\t|  " DHCP_DEBUG_COLOR "OP" NONE "  |" DHCP_DEBUG_COLOR "HTYPE" NONE
		   " | " DHCP_DEBUG_COLOR "HLEN" NONE " | " DHCP_DEBUG_COLOR "HOPS" NONE " |\n");
	printf("\t| " DHCP_DEBUG_COLOR "0x%02x" NONE " | " DHCP_DEBUG_COLOR "0x%02x" NONE
		   " | " DHCP_DEBUG_COLOR "0x%02x" NONE " | " DHCP_DEBUG_COLOR "0x%02x" NONE " |\n",
		   header.op, header.hdr_type, header.hdr_len, header.hops);
	printf("\t|                           |\n");
	printf("\t|" DHCP_DEBUG_COLOR "XID" NONE "=" DHCP_DEBUG_COLOR "0x%02x%02x%02x%02x" NONE
		   "             |\n",
		   header.xid[0], header.xid[1], header.xid[2], header.xid[3]);
	if (GET_IP(header.yiaddr) != 0) {
		printf("\t|" DHCP_DEBUG_COLOR "YIADDR" NONE "=" IP_DEBUG_COLOR "%-16s" NONE "    |\n",
			   ip_addr_to_string(header.yiaddr, NULL));
	}
	printf("\t|" DHCP_DEBUG_COLOR "CHADDR" NONE "=" ETH_DEBUG_COLOR "%s" NONE "   |\n",
		   eth_addr_to_string(header.chaddr, NULL));
	printf("\t|==========" DHCP_DEBUG_COLOR "OPTIONS" NONE "==========|\n");

	return;
}
#endif

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
	netdevice_t *device;

	// Return DHCP_ERROR_NULL if udp_init() error
	if ((device = udp_init()) == UDP_ERROR_NULL) {
		fprintf(stderr, ERR_COLOR "%s:%d in %s(): udp_init() error\n" NONE, __FILE__, __LINE__,
				__func__);
		return DHCP_ERROR_NULL;
	}

	// Regist DHCP client to UDP
	if (udp_add_protocol(UDP_PORT_DHCP_C, dhcp_client_main, "DHCP") == UDP_ERROR) {
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
 * @return 0 on success,
 * DHCP_ERROR if there's still a conversation
 */
int dhcp_discover(const byte *my_mac) {
	// Return if there is still a conversation going
	if (*(u_int *)dhcp_req_que.xid_waiting != 0) {
		return DHCP_ERROR;
	}

	dhcp_hdr_t header;	 // DHCP header to send

	/**
	 * Fill in the data
	 */
	header.op = DHCP_OP_TO_SERVER;
	header.hdr_type = ETH_HDR_TYPE;
	header.hdr_len = ETH_ADDR_LEN;
	header.hops = 0;
	*(u_int *)(dhcp_req_que.xid_waiting) = rand();
	memcpy(header.xid, &dhcp_req_que.xid_waiting, DHCP_XID_LEN);
	// memcpy(header.xid, &xid_waiting, DHCP_XID_LEN);
	header.secs = 0;
	header.flags = 0;

	GET_IP(header.ciaddr) = 0;
	GET_IP(header.yiaddr) = 0;
	GET_IP(header.siaddr) = 0;
	GET_IP(header.giaddr) = 0;
	memcpy(header.chaddr, my_mac, ETH_ADDR_LEN);

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
	dhcp_send(DHCP_MSG.DISCOVER, buf, dhcp_discover_len);

	return 0;
}

/**
 * Send a DHCP Request message
 * @param req_ip IP Requested
 */
void dhcp_request(const byte *req_ip, const byte *my_mac) {
	dhcp_hdr_t header;	 // DHCP header to send

	/**
	 * Fill in the data
	 */
	header.op = DHCP_OP_TO_SERVER;
	header.hdr_type = ETH_HDR_TYPE;
	header.hdr_len = ETH_ADDR_LEN;
	header.hops = 0;
	memcpy(header.xid, &dhcp_req_que.xid_waiting, DHCP_XID_LEN);
	// memcpy(header.xid, &dhcp_req_que.xid_waiting, DHCP_XID_LEN);
	header.secs = 0;
	header.flags = 0;

	GET_IP(header.ciaddr) = 0;
	GET_IP(header.yiaddr) = 0;
	GET_IP(header.siaddr) = 0;
	GET_IP(header.giaddr) = 0;
	memcpy(header.chaddr, my_mac, ETH_ADDR_LEN);

	memset(header.sname, 0, DHCP_SNAME_LEN);
	memset(header.file, 0, DHCP_FILE_LEN);

	// Total length of DHCP request packet
	int dhcp_request_len = sizeof(dhcp_hdr_t) + 20;

	// DHCP discove packet buffer
	byte buf[dhcp_request_len];

	// Fill in the header
	memcpy(buf, &header, sizeof(dhcp_hdr_t));

	// Fill in the DHCP Magic Cookie
	int offset = sizeof(dhcp_hdr_t);   // Offset of the buf
	memcpy(buf + offset, DHCP_MAGIC_COOKIE, 4);

	// Update the offset
	offset += 4;
	// Fill in the Message type
	offset += dhcp_op_filler(buf + offset, DHCP_OP.Message_Type, 1, &DHCP_MSG.REQUEST);
	// Fill in the Required IP address
	offset += dhcp_op_filler(buf + offset, DHCP_OP.Address_Request, 1, req_ip);
	// Fill in the Server ID
	// offset += dhcp_op_filler(buf + offset, DHCP_OP.Server_Identifier, 1, dhcp_req_que.server_id);
	// Fill in the End option
	dhcp_op_filler(buf + offset, DHCP_OP.End, 1, NULL);

	// Send out the DHCP discover
	dhcp_send(DHCP_MSG.DISCOVER, buf, dhcp_request_len);

	return;
}

/**
 * Send DHCP packet with specify DHCP message type
 * @param msg_type Message type
 * @param data DHCP packet
 * @param data_len Length DHCP packet
 * @return 0 on success,
 * DHCP_ERROR if udp_send() error
 */
int dhcp_send(byte msg_type, const byte *data, u_int data_len) {
	udp_param_t udp_param;	 // UDP parameter

	/**
	 * Fill in UDP parameters according
	 * to different DHCP message type
	 */
	if (msg_type == DHCP_MSG.DISCOVER) {
		IP_COPY(udp_param.src_ip, string_to_ip_addr("0.0.0.0"));
		IP_COPY(udp_param.dst_ip, string_to_ip_addr("255.255.255.255"));
		udp_param.src_port = UDP_PORT_DHCP_C;
		udp_param.dst_port = UDP_PORT_DHCP_S;
	} else if (msg_type == DHCP_MSG.OFFER) {
		IP_COPY(udp_param.src_ip, MY_IPV4_INFO.my_ip_addr);
		IP_COPY(udp_param.dst_ip, string_to_ip_addr("255.255.255.255"));
		udp_param.src_port = UDP_PORT_DHCP_S;
		udp_param.dst_port = UDP_PORT_DHCP_C;
	} else if (msg_type == DHCP_MSG.REQUEST) {
		IP_COPY(udp_param.src_ip, string_to_ip_addr("0.0.0.0"));
		IP_COPY(udp_param.dst_ip, string_to_ip_addr("255.255.255.255"));
		udp_param.src_port = UDP_PORT_DHCP_C;
		udp_param.dst_port = UDP_PORT_DHCP_S;
	} else if (msg_type == DHCP_MSG.ACK) {
		IP_COPY(udp_param.src_ip, MY_IPV4_INFO.my_ip_addr);
		// Should be client IP address!!
		IP_COPY(udp_param.dst_ip, string_to_ip_addr("255.255.255.255"));
		udp_param.src_port = UDP_PORT_DHCP_S;
		udp_param.dst_port = UDP_PORT_DHCP_C;
	}

#if (DEBUG_DHCP_SEND == 1)
	dhcp_client_main(data, data_len);
#endif

	if (udp_send(udp_param, data, data_len) == UDP_ERROR) {
		fprintf(stderr, ERR_COLOR "%s:%d in %s(): udp_send() error\n" NONE, __FILE__, __LINE__,
				__func__);
		return DHCP_ERROR;
	}

	return 0;
}

/**
 * DHCP client capture handle
 * @param dhcp_msg DHCP message
 * @param msg_len Length of message
 */
void dhcp_client_main(const byte *dhcp_msg, u_int msg_len) {
	// DHCP header
	dhcp_hdr_t header = *(dhcp_hdr_t *)dhcp_msg;
	// Options' offset in DHCP message
	u_int op_offset = sizeof(dhcp_hdr_t) + DHCP_MAGIC_LEN;
	// Length of options
	u_int op_len = msg_len - op_offset;
	// Options buffer
	byte options[op_len];
	// Iterator of options
	byte *op_it = options;

	// Copy the Options into buffer
	memcpy(options, dhcp_msg + op_offset, op_len);

#if (DEBUG_DHCP_HEADER == 1)
	if (header.op == DHCP_OP_TO_CLIENT)
		printf(DHCP_2_DEBUG_COLOR "DHCP Received\n" NONE);
	else
		printf(DHCP_2_DEBUG_COLOR "DHCP Send\n" NONE);

	dhcp_dump(header);
#endif

	set_ack_info_my_ip(header.yiaddr);
	set_chaddr(header.chaddr);

	while (*op_it != DHCP_OP.End) {
		op_it += dhcp_op_list[*op_it].handler(op_it);
	}
	dhcp_op_list[*op_it].handler(op_it);

	if (get_msg_type() == DHCP_MSG.OFFER) {
		if (memcmp(dhcp_req_que.xid_waiting, header.xid, DHCP_XID_LEN) == 0) {
			dhcp_request(header.yiaddr, header.chaddr);
		}
	} else if (get_msg_type() == DHCP_MSG.ACK) {
		memset(dhcp_req_que.xid_waiting, 0, DHCP_XID_LEN);
	}

	return;
}