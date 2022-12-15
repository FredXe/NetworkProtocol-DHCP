#include "dhcp_op.h"

#include "util.h"

const dhcp_op_code_t DHCP_OP = {0, 1, 3, 6, 15, 50, 51, 53, 54, 55, 255};
const dhcp_msg_t DHCP_MSG = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18};

void dhcp_op_init(dhcp_op_t **list_ptr) {
	if (*list_ptr != NULL) {
		fprintf(stderr,
				ERR_COLOR "%s:%d in %s(): list has been initialized, this function should "
						  "only be called once\n" NONE,
				__FILE__, __LINE__, __func__);
		return;
	}

	dhcp_op_t *list = *list_ptr = (dhcp_op_t *)calloc(256, sizeof(dhcp_op_t));

	strcpy(list[DHCP_OP.Pad].name, "Pad");
	list[DHCP_OP.Pad].length = 0;
	list[DHCP_OP.Pad].len_mul = 0;

	strcpy(list[DHCP_OP.Subnet_Mask].name, "Subnet Mask");
	list[DHCP_OP.Subnet_Mask].length = 4;
	list[DHCP_OP.Subnet_Mask].len_mul = 0;

	strcpy(list[DHCP_OP.Router].name, "Router");
	list[DHCP_OP.Router].length = 4;
	list[DHCP_OP.Router].len_mul = 1;

	strcpy(list[DHCP_OP.Domain_Name_Server].name, "Domain Name Server");
	list[DHCP_OP.Domain_Name_Server].length = 4;
	list[DHCP_OP.Domain_Name_Server].len_mul = 1;

	strcpy(list[DHCP_OP.Domain_Name].name, "Domain Name");
	list[DHCP_OP.Domain_Name].length = 1;
	list[DHCP_OP.Domain_Name].len_mul = 1;

	strcpy(list[DHCP_OP.Address_Request].name, "Address Request");
	list[DHCP_OP.Address_Request].length = 4;
	list[DHCP_OP.Address_Request].len_mul = 0;

	strcpy(list[DHCP_OP.Address_Time].name, "Address Time");
	list[DHCP_OP.Address_Time].length = 4;
	list[DHCP_OP.Address_Time].len_mul = 0;

	strcpy(list[DHCP_OP.Message_Type].name, "DHCP Message Type");
	list[DHCP_OP.Message_Type].length = 1;
	list[DHCP_OP.Message_Type].len_mul = 0;

	strcpy(list[DHCP_OP.Server_Identifier].name, "DHCP Server Identifier");
	list[DHCP_OP.Server_Identifier].length = 4;
	list[DHCP_OP.Server_Identifier].len_mul = 0;

	strcpy(list[DHCP_OP.Parameter_List].name, "Parameter List");
	list[DHCP_OP.Parameter_List].length = 1;
	list[DHCP_OP.Parameter_List].len_mul = 1;

	strcpy(list[DHCP_OP.End].name, "End");
	list[DHCP_OP.End].length = 0;
	list[DHCP_OP.End].len_mul = 0;

	return;
}