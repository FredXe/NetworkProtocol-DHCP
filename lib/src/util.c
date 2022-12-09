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
 * @param buf String buffer to be use
 * @return ip_addr in *.*.*.* format string
 */
const char *ip_addr_to_string(byte *ip_addr, char *buf) {
	static char ip_buf[16];
	if (buf == NULL)
		buf = ip_buf;
	sprintf(buf, "%d.%d.%d.%d", (int)ip_addr[0], (int)ip_addr[1], (int)ip_addr[2], (int)ip_addr[3]);
	return buf;
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
 * @param buf String buffer to be use
 * @return eth_addr in **:**:**:**:**:** format string
 */
const char *eth_addr_to_string(const byte *eth_addr, char *buf) {
	static char eth_buf[18];
	if (buf == NULL)
		buf = eth_buf;
	sprintf(buf, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", eth_addr[0], eth_addr[1], eth_addr[2],
			eth_addr[3], eth_addr[4], eth_addr[5]);
	return buf;
}

/**
 * Print out the data in hex base with specific format
 * @param data Bytes pointer would be printed
 * @param data_len Length of data
 */
void print_data(const byte *data, const u_int data_len) {
	int i;
	printf("\t");
	for (i = 0; i < data_len; i++) {
		printf("%.2x ", data[i]);
		if ((i + 1) % MAX_LINE_LEN == 0) {
			printf("\n");
			if (i + 1 < data_len)
				printf("\t");
		} else if ((i + 1) % MAX_LINE_LEN == 8) {
			printf(" ");
		}
	}

	/**
	 * Print new line if the end of output stream
	 * is not a new line
	 */
	if (i % MAX_LINE_LEN != 0) {
		printf("\n");
	}
}

/**
 * Switch byte arrangement from
 * Little-endian => Big-endian
 * @param in Input 2 bytes
 * @return swaped bytes
 */
two_bytes swap16(two_bytes in) {
	return ((in << 8) | (in >> 8));
}
