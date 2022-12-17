#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdlib.h>

#include "ip.h"
#include "netdevice.h"
#include "types.h"

#define ETH_BUF_LEN 18
#define MAC_BUF_LEN 18
#define IP_BUF_LEN	16

#define NONE		 "\033[m"
#define RED			 "\033[0;31m"
#define LIGHT_RED	 "\033[1;31m"
#define GREEN		 "\033[0;32m"
#define LIGHT_GREEN	 "\033[1;32m"
#define BLUE		 "\033[0;34m"
#define LIGHT_BLUE	 "\033[1;34m"
#define GRAY		 "\033[0;30m"
#define DARK_GRAY	 "\033[1;30m"
#define CYAN		 "\033[0;36m"
#define LIGHT_CYAN	 "\033[1;36m"
#define PURPLE		 "\033[0;35m"
#define LIGHT_PURPLE "\033[1;35m"
#define YELLOW		 "\033[0;33m"
#define LIGHT_YELLOW "\033[1;33m"
#define LIGHT_GRAY	 "\033[0;37m"
#define WHITE		 "\033[1;37m"

#define ETH_DEBUG_COLOR	  BLUE		   // Color for netdevice debug message
#define ETH_2_DEBUG_COLOR LIGHT_BLUE   // Secondary color for netdevice debug message

#define ARP_DEBUG_COLOR	  CYAN		   // Color for ARP debug message
#define ARP_2_DEBUG_COLOR LIGHT_CYAN   // Secondary color for ARP debug message

#define IP_DEBUG_COLOR	 GREEN		   // Color for IP debug message
#define IP_2_DEBUG_COLOR LIGHT_GREEN   // Secondary color for IP debug message

#define UDP_DEBUG_COLOR	  PURPLE		 // Color for UDP debug message
#define UDP_2_DEBUG_COLOR LIGHT_PURPLE	 // Secondary color for UDP debug message

#define DHCP_DEBUG_COLOR   YELLOW		  // Color for DHCP debug message
#define DHCP_2_DEBUG_COLOR LIGHT_YELLOW	  // Secondary color for DHCP debug message

#define ERR_COLOR LIGHT_RED	  // Color for error message

#define MAX_LINE_LEN 16	  // MAX bytes print in one line

#define MAX_INPUT_LEN 256	// MAX Length of one line input

#define GET_IP(ip_addr) (*((ip_addr_t *)(ip_addr)))

#define MAX(A, B) ((A > B) ? A : B)
#define MIN(A, B) ((A < B) ? A : B)

extern ipv4_info_t MY_IPV4_INFO;
extern byte MY_MAC_ADDR[ETH_ADDR_LEN];

/*================
 * Public Methods
 *================*/
extern int readready();
extern const byte *set_my_mac(const netdevice_t *device);
extern const byte *get_my_ip(const netdevice_t *device);
extern const int get_my_ip_info(ipv4_info_t *info);
extern const byte *string_to_ip_addr(const char *ip_addr_str);
extern const char *ip_addr_to_string(const byte *ip_addr, char *buf);
extern const byte *string_to_eth_addr(const char *eth_addr_str);
extern const char *eth_addr_to_string(const byte *eth_addr, char *buf);
extern void print_data(const byte *data, const u_int data_len);
extern two_bytes swap16(two_bytes in);
extern u_int swap32(u_int in);
extern two_bytes checksum(byte *data, u_int len);

#endif
