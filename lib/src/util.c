#include "util.h"

#include <stdio.h>
#include <string.h>

#include "ip.h"

const byte *get_my_ip(netdevice_t *device) {
	return string_to_ip_addr("192.168.1.116");
}

/**
 * Convert string into byte array
 * @param ip_addr_str *.*.*.* format string
 * @return byte* point to ip_addr,
 * NULL on error
 */
const byte *string_to_ip_addr(const char *ip_addr_str) {
	if (strlen(ip_addr_str) > 15) {
		fprintf(stderr, "%s:%d in %s(): length of ip_addr_str exceed\n", __FILE__, __LINE__,
				__func__);
		return NULL;
	}
	static byte ip_buf[IP_ADDR_LEN];
	int int_buf[IP_ADDR_LEN];
	sscanf(ip_addr_str, "%d.%d.%d.%d", int_buf, int_buf + 1, int_buf + 2, int_buf + 3);
	ip_buf[0] = int_buf[0];
	ip_buf[1] = int_buf[1];
	ip_buf[2] = int_buf[2];
	ip_buf[3] = int_buf[3];
	return ip_buf;
}

/**
 * Convert byte array IP address into string
 * @param ip_addr IP address in bits form
 * @return ip_addr in *.*.*.* format string
 */
const char *ip_addr_to_string(byte *ip_addr) {
	static char ip_buf[16];
	sprintf(ip_buf, "%d.%d.%d.%d", (int)ip_addr[0], (int)ip_addr[1], (int)ip_addr[2],
			(int)ip_addr[3]);
	return ip_buf;
}

/**
 * Convert string into byte array
 * @param eth_addr_str **:**:**:**:**:** format string
 * @return byte* point to eth_addr,
 * NULL on error
 */
const byte *string_to_eth_addr(const char *eth_addr_str) {
	if (strlen(eth_addr_str) != 17) {
		fprintf(stderr, "%s:%d in %s(): length of eth_addr_str invalid\n", __FILE__, __LINE__,
				__func__);
		return NULL;
	}
	static byte eth_buf[ETH_ADDR_LEN];
	int int_buf[ETH_ADDR_LEN];
	sscanf(eth_addr_str, "%x:%x:%x:%x:%x:%x", int_buf, int_buf + 1, int_buf + 2, int_buf + 3,
		   int_buf + 4, int_buf + 5);
	eth_buf[0] = int_buf[0];
	eth_buf[1] = int_buf[1];
	eth_buf[2] = int_buf[2];
	eth_buf[3] = int_buf[3];
	eth_buf[4] = int_buf[4];
	eth_buf[5] = int_buf[5];
	return eth_buf;
}

/**
 * Convert byte array MAC address into string
 * @param eth_addr MAC address in bits form
 * @return eth_addr in **:**:**:**:**:** format string
 */
const char *eth_addr_to_string(byte *eth_addr) {
	static char eth_buf[18];
	sprintf(eth_buf, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", eth_addr[0], eth_addr[1], eth_addr[2],
			eth_addr[3], eth_addr[4], eth_addr[5]);
	return eth_buf;
}