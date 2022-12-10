#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdlib.h>

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
#define DARY_GRAY	 "\033[1;30m"
#define CYAN		 "\033[0;36m"
#define LIGHT_CYAN	 "\033[1;36m"
#define PURPLE		 "\033[0;35m"
#define LIGHT_PURPLE "\033[1;35m"
#define BROWN		 "\033[0;33m"
#define YELLOW		 "\033[1;33m"
#define LIGHT_GRAY	 "\033[0;37m"
#define WHITE		 "\033[1;37m"

#define ETH_DEBUG_COLOR	  BLUE		   // Color for netdevice debug message
#define ETH_2_DEBUG_COLOR LIGHT_BLUE   // Secondary color for netdevice debug message

#define ARP_DEBUG_COLOR	  CYAN		   // Color for ARP debug message
#define ARP_2_DEBUG_COLOR LIGHT_CYAN   // Secondary color for ARP debug message

#define IP_DEBUG_COLOR	 GREEN		   // Color for IP debug message
#define IP_2_DEBUG_COLOR LIGHT_GREEN   // Secondary color for IP debug message

#define ERR_COLOR LIGHT_RED	  // Color for error message

#define MAX_LINE_LEN 16	  // MAX bytes print in one line

#define GET_IP(ip_addr) (*((ip_addr_t *)(ip_addr)))

#define MAX(A, B) ((A > B) ? A : B)
#define MIN(A, B) ((A < B) ? A : B)

/*================
 * Public Methods
 *================*/
extern const byte *get_my_ip(netdevice_t *device);
extern const byte *string_to_ip_addr(const char *ip_addr_str);
extern const char *ip_addr_to_string(byte *ip_addr, char *buf);
extern const byte *string_to_eth_addr(const char *eth_addr_str);
extern const char *eth_addr_to_string(const byte *eth_addr, char *buf);
extern void print_data(const byte *data, const u_int data_len);
extern two_bytes swap16(two_bytes in);

#endif
