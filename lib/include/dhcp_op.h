#ifndef __DHCP_OP_H__
#define __DHCP_OP_H__

#include "types.h"

typedef u_int (*dhcp_op_handler)(const byte *option);

typedef struct {
	char name[32];	 // Name of the Option
	byte length;	 // One unit of an element
	byte len_mul;	 // 0 if the length is constant, 1 if variable
	// It's handler that we call it when we receive it
	dhcp_op_handler handler;
} dhcp_op_t;   // DHCP Option's information, and handler

#define DHCP_OP_TAG_NUM 11	 // Number of Tags we defined

typedef struct {
	const byte Pad;					  // 0
	const byte Subnet_Mask;			  // 1
	const byte Router;				  // 3
	const byte Domain_Name_Server;	  // 6
	const byte Domain_Name;			  // 15
	const byte Address_Request;		  // 50
	const byte Address_Time;		  // 51
	const byte Message_Type;		  // 53
	const byte Server_Identifier;	  // 54
	const byte Parameter_List;		  // 55
	const byte End;					  // 255
} dhcp_op_tag_t;					  // DHCP Option Tag type
extern const dhcp_op_tag_t DHCP_OP;	  // DHCP Option Tag constant

#define DHCP_MSG_NAME_LEN 32   // Length of DHCP Message

typedef struct {
	const byte DISCOVER;			//  1
	const byte OFFER;				//  2
	const byte REQUEST;				//  3
	const byte DECLINE;				//  4
	const byte ACK;					//  5
	const byte NAK;					//  6
	const byte RELEASE;				//  7
	const byte INFORM;				//  8
	const byte FORCERENEW;			//  9
	const byte LEASEQUERY;			//  10
	const byte LEASEUNASSIGNED;		//  11
	const byte LEASEUNKNOWN;		//  12
	const byte LEASEACTIVE;			//  13
	const byte BULKLEASEQUERY;		//  14
	const byte LEASEQUERYDONE;		//  15
	const byte ACTIVELEASEQUERY;	//  16
	const byte LEASEQUERYSTATUS;	//  17
	const byte TLS;					//  18
} dhcp_msg_t;						// DHCP Message type
extern const dhcp_msg_t DHCP_MSG;	// DHCP Message constant
// List that reference DHCP Message Type to String
extern char DHCP_MSG_NAME[19][DHCP_MSG_NAME_LEN];

extern void dhcp_op_init(dhcp_op_t **list_ptr);
extern byte get_msg_type();
extern void set_ack_info_my_ip(const byte *my_ip);
extern void set_chaddr(const byte *chaddr);

#endif