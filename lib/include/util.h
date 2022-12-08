#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdlib.h>

#include "netdevice.h"
#include "types.h"

#define ETH_IPV4 0x0008
#define ETH_ARP	 0x0608

#define ETH_BUF_LEN 18
#define MAC_BUF_LEN 18
#define IP_BUF_LEN	16

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
extern const char *eth_addr_to_string(byte *eth_addr, char *buf);
extern two_bytes swap16(two_bytes in);

#endif
