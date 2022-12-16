#include "dhcp_op.h"

#include "util.h"

const dhcp_op_tag_t DHCP_OP = {0, 1, 3, 6, 15, 50, 51, 53, 54, 55, 255};
const dhcp_msg_t DHCP_MSG = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18};
char DHCP_MSG_NAME[19][DHCP_MSG_NAME_LEN] = {"NONE",
											 "DISCOVER",
											 "OFFER",
											 "REQUEST",
											 "DECLINE",
											 "ACK",
											 "NAK",
											 "RELEASE",
											 "INFORM",
											 "FORCERENEW",
											 "LEASEQUERY",
											 "LEASEUNASSIGNED",
											 "LEASEUNKNOWN",
											 "LEASEACTIVE",
											 "BULKLEASEQUERY",
											 "LEASEQUERYDONE",
											 "ACTIVELEASEQUERY",
											 "LEASEQUERYSTATUS",
											 "TLS"};
static dhcp_op_t *dhcp_op_list = NULL;

static u_int default_h(const byte *option);
static u_int pad_h(const byte *option);
static u_int subnet_mask_h(const byte *option);
static u_int router_h(const byte *option);
static u_int dns_h(const byte *option);
static u_int domain_name_h(const byte *option);
static u_int address_req_h(const byte *option);
static u_int address_time_h(const byte *option);
static u_int message_type_h(const byte *option);
static u_int server_id_h(const byte *option);
static u_int param_list_h(const byte *option);
static u_int end_h(const byte *option);

static struct dhcp_ack_info_t {
	byte msg_type;
	byte my_ip[IP_ADDR_LEN];
	byte router[IP_ADDR_LEN];
	byte subnet_mask[IP_ADDR_LEN];
	byte dns_server[IP_ADDR_LEN];
	byte dhcp_server_id[IP_ADDR_LEN];

} dhcp_ack_info;

/**
 * Initialize the DHCP Option list by
 * filling the data.
 * @param list_ptr
 */
void dhcp_op_init(dhcp_op_t **list_ptr) {
	if (*list_ptr != NULL) {
		fprintf(stderr,
				ERR_COLOR "%s:%d in %s(): list has been initialized, this function should "
						  "only be called once\n" NONE,
				__FILE__, __LINE__, __func__);
		return;
	}

	dhcp_op_t *list = *list_ptr = (dhcp_op_t *)calloc(256, sizeof(dhcp_op_t));

	for (int i = 0; i < 256; i++) {
		list[i].handler = default_h;
	}

	strcpy(list[DHCP_OP.Pad].name, "Pad");
	list[DHCP_OP.Pad].length = 0;
	list[DHCP_OP.Pad].len_mul = 0;
	list[DHCP_OP.Pad].handler = pad_h;

	strcpy(list[DHCP_OP.Subnet_Mask].name, "Subnet Mask");
	list[DHCP_OP.Subnet_Mask].length = 4;
	list[DHCP_OP.Subnet_Mask].len_mul = 0;
	list[DHCP_OP.Subnet_Mask].handler = subnet_mask_h;

	strcpy(list[DHCP_OP.Router].name, "Router");
	list[DHCP_OP.Router].length = 4;
	list[DHCP_OP.Router].len_mul = 1;
	list[DHCP_OP.Router].handler = router_h;

	strcpy(list[DHCP_OP.Domain_Name_Server].name, "Domain Name Server");
	list[DHCP_OP.Domain_Name_Server].length = 4;
	list[DHCP_OP.Domain_Name_Server].len_mul = 1;
	list[DHCP_OP.Domain_Name_Server].handler = dns_h;

	strcpy(list[DHCP_OP.Domain_Name].name, "Domain Name");
	list[DHCP_OP.Domain_Name].length = 1;
	list[DHCP_OP.Domain_Name].len_mul = 1;
	list[DHCP_OP.Domain_Name].handler = domain_name_h;

	strcpy(list[DHCP_OP.Address_Request].name, "Address Request");
	list[DHCP_OP.Address_Request].length = 4;
	list[DHCP_OP.Address_Request].len_mul = 0;
	list[DHCP_OP.Address_Request].handler = address_req_h;

	strcpy(list[DHCP_OP.Address_Time].name, "Address Time");
	list[DHCP_OP.Address_Time].length = 4;
	list[DHCP_OP.Address_Time].len_mul = 0;
	list[DHCP_OP.Address_Time].handler = address_time_h;

	strcpy(list[DHCP_OP.Message_Type].name, "DHCP Message Type");
	list[DHCP_OP.Message_Type].length = 1;
	list[DHCP_OP.Message_Type].len_mul = 0;
	list[DHCP_OP.Message_Type].handler = message_type_h;

	strcpy(list[DHCP_OP.Server_Identifier].name, "DHCP Server Identifier");
	list[DHCP_OP.Server_Identifier].length = 4;
	list[DHCP_OP.Server_Identifier].len_mul = 0;
	list[DHCP_OP.Server_Identifier].handler = server_id_h;

	strcpy(list[DHCP_OP.Parameter_List].name, "Parameter List");
	list[DHCP_OP.Parameter_List].length = 1;
	list[DHCP_OP.Parameter_List].len_mul = 1;
	list[DHCP_OP.Parameter_List].handler = param_list_h;

	strcpy(list[DHCP_OP.End].name, "End");
	list[DHCP_OP.End].length = 0;
	list[DHCP_OP.End].len_mul = 0;
	list[DHCP_OP.End].handler = end_h;

	dhcp_op_list = list;
	return;
}

byte get_msg_type() {
	return dhcp_ack_info.msg_type;
}

void set_ack_info_my_ip(const byte *my_ip) {
	IP_COPY(dhcp_ack_info.my_ip, my_ip);
}

u_int default_h(const byte *option) {
	byte len = *(option + 1);
	return len + 2;
}

uint pad_h(const byte *option) {
	return 1;
}

uint subnet_mask_h(const byte *option) {
	byte op_tag = *option;
	byte len = *(option + 1);
	byte value[len];
	memcpy(value, option + 2, len);

#if (DEBUG_DHCP_OPTIONS == 1)
	printf("\t" DHCP_DEBUG_COLOR "Subnet Mask" NONE ": " IP_DEBUG_COLOR "%s" NONE "\n",
		   ip_addr_to_string(value, NULL));
#endif

	IP_COPY(dhcp_ack_info.subnet_mask, value);

	return len + 2;
}

uint router_h(const byte *option) {
	byte op_tag = *option;
	byte len = *(option + 1);
	byte value[len];
	memcpy(value, option + 2, len);

#if (DEBUG_DHCP_OPTIONS == 1)
	for (int offset = 0; offset < len; offset += IP_ADDR_LEN) {
		printf("\t" DHCP_DEBUG_COLOR "Router #%d" NONE ": " IP_DEBUG_COLOR "%s" NONE "\n",
			   (offset) / 4 + 1, ip_addr_to_string(value + offset, NULL));
	}
#endif

	IP_COPY(dhcp_ack_info.router, value);

	return len + 2;
}

uint dns_h(const byte *option) {
	byte op_tag = *option;
	byte len = *(option + 1);
	byte value[len];
	memcpy(value, option + 2, len);

#if (DEBUG_DHCP_OPTIONS == 1)
	for (int offset = 0; offset < len; offset += IP_ADDR_LEN) {
		printf("\t" DHCP_DEBUG_COLOR "DNS Server #%d" NONE ": " IP_DEBUG_COLOR "%s" NONE "\n",
			   (offset) / 4 + 1, ip_addr_to_string(value + offset, NULL));
	}
#endif

	IP_COPY(dhcp_ack_info.dns_server, value);

	return len + 2;
}

uint domain_name_h(const byte *option) {
	byte len = *(option + 1);
	return len + 2;
}
uint address_req_h(const byte *option) {
	byte op_tag = *option;
	byte len = *(option + 1);
	byte value[len];
	memcpy(value, option + 2, len);

#if (DEBUG_DHCP_OPTIONS == 1)
	printf("\t" DHCP_DEBUG_COLOR "Address Request" NONE ": " IP_DEBUG_COLOR "%ss" NONE "\n",
		   ip_addr_to_string(value, NULL));
#endif

	return len + 2;
}

uint address_time_h(const byte *option) {
	byte op_tag = *option;
	byte len = *(option + 1);
	byte value[len];
	memcpy(value, option + 2, len);

#if (DEBUG_DHCP_OPTIONS == 1)
	printf("\t" DHCP_DEBUG_COLOR "Address Time" NONE ": " DHCP_DEBUG_COLOR "%ds" NONE "\n",
		   swap32(*(u_int *)value));
#endif

	return len + 2;
}

uint message_type_h(const byte *option) {
	byte op_tag = *option;
	byte len = *(option + 1);
	byte value[len];
	memcpy(value, option + 2, len);

#if (DEBUG_DHCP_OPTIONS == 1)
	printf("\t" DHCP_DEBUG_COLOR "Message Type" NONE ": " DHCP_DEBUG_COLOR "%s" NONE "\n",
		   DHCP_MSG_NAME[value[0]]);
#endif

	dhcp_ack_info.msg_type = value[0];

	return len + 2;
}

uint server_id_h(const byte *option) {
	byte op_tag = *option;
	byte len = *(option + 1);
	byte value[len];
	memcpy(value, option + 2, len);

#if (DEBUG_DHCP_OPTIONS == 1)
	printf("\t" DHCP_DEBUG_COLOR "Server ID" NONE ": " IP_DEBUG_COLOR "%s" NONE "\n",
		   ip_addr_to_string(value, NULL));
#endif

	IP_COPY(dhcp_ack_info.dhcp_server_id, value);

	return len + 2;
}

uint param_list_h(const byte *option) {
	byte op_tag = *option;
	byte len = *(option + 1);
	byte value[len];
	memcpy(value, option + 2, len);

#if (DEBUG_DHCP_OPTIONS == 1)
	printf("\t" DHCP_DEBUG_COLOR "Parameter Request List" NONE ":" DHCP_DEBUG_COLOR "\n");

	for (int i = 0; i < len; i++) {
		printf("\t\t%s (%d)", dhcp_op_list[*(value + i)].name, *(value + i));
	}
#endif

	return len + 2;
}

uint end_h(const byte *option) {
#if (DEBUG_DHCP_OPTIONS == 1)
	printf("\t" DHCP_DEBUG_COLOR "End" NONE "\n");
#endif

	if (dhcp_ack_info.msg_type != DHCP_MSG.ACK) {
		return 1;
	}

	// Set the IPv4 information from DHCP ACK message
	IP_COPY(MY_IPV4_INFO.my_ip_addr, dhcp_ack_info.my_ip);
	IP_COPY(MY_IPV4_INFO.gateway_d, dhcp_ack_info.router);
	IP_COPY(MY_IPV4_INFO.dns_server, dhcp_ack_info.dns_server);
	IP_COPY(MY_IPV4_INFO.subnet_mask, dhcp_ack_info.subnet_mask);
	GET_IP(MY_IPV4_INFO.subnet) = GET_IP(dhcp_ack_info.my_ip) & GET_IP(dhcp_ack_info.subnet_mask);

#if (DEBUG_DHCP == 1)
	char my_ip[IP_BUF_LEN], router[IP_BUF_LEN], dns[IP_BUF_LEN], subnet_m[IP_BUF_LEN],
		subnet[IP_BUF_LEN];
	printf(DHCP_DEBUG_COLOR "IPv4 info set" NONE ":\n");
	printf("\t" IP_DEBUG_COLOR "My IP" NONE ": " IP_DEBUG_COLOR "%s" NONE "\n",
		   ip_addr_to_string(MY_IPV4_INFO.my_ip_addr, my_ip));
	printf("\t" IP_DEBUG_COLOR "Router" NONE ": " IP_DEBUG_COLOR "%s" NONE "\n",
		   ip_addr_to_string(MY_IPV4_INFO.gateway_d, router));
	printf("\t" IP_DEBUG_COLOR "DNS Server" NONE ": " IP_DEBUG_COLOR "%s" NONE "\n",
		   ip_addr_to_string(MY_IPV4_INFO.dns_server, dns));
	printf("\t" IP_DEBUG_COLOR "Subnet Mask" NONE ": " IP_DEBUG_COLOR "%s" NONE "\n",
		   ip_addr_to_string(MY_IPV4_INFO.subnet_mask, subnet_m));
	printf("\t" IP_DEBUG_COLOR "Subnet" NONE ": " IP_DEBUG_COLOR "%s" NONE "\n",
		   ip_addr_to_string(MY_IPV4_INFO.subnet, subnet));
#endif

	return 1;
}