#ifndef __DHCP_OP_H__
#define __DHCP_OP_H__

#include "types.h"

typedef int (*dhcp_op_handler)(const byte *data, u_int length);

typedef struct {
	char name[32];
	byte length;
	byte len_mul;
	dhcp_op_handler handler;
} dhcp_op_t;

typedef struct {
	byte Pad;				   // 0
	byte Subnet_Mask;		   // 1
	byte Router;			   // 3
	byte Domain_Name_Server;   // 6
	byte Domain_Name;		   // 15
	byte Address_Request;	   // 50
	byte Address_Time;		   // 51
	byte Message_Type;		   // 53
	byte Server_Identifier;	   // 54
	byte Parameter_List;	   // 55
	byte End;				   // 255
} dhcp_op_code_t;
extern const dhcp_op_code_t DHCP_OP;

typedef struct {
	byte DISCOVER;			 //  1
	byte OFFER;				 //  2
	byte REQUEST;			 //  3
	byte DECLINE;			 //  4
	byte ACK;				 //  5
	byte NAK;				 //  6
	byte RELEASE;			 //  7
	byte INFORM;			 //  8
	byte FORCERENEW;		 //  9
	byte LEASEQUERY;		 //  10
	byte LEASEUNASSIGNED;	 //  11
	byte LEASEUNKNOWN;		 //  12
	byte LEASEACTIVE;		 //  13
	byte BULKLEASEQUERY;	 //  14
	byte LEASEQUERYDONE;	 //  15
	byte ACTIVELEASEQUERY;	 //  16
	byte LEASEQUERYSTATUS;	 //  17
	byte TLS;				 //  18
} dhcp_msg_t;
extern const dhcp_msg_t DHCP_MSG;

extern void dhcp_op_init(dhcp_op_t **list_ptr);

#endif