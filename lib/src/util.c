#include "util.h"

#include <stdio.h>
#include <string.h>

#include "ip.h"

const byte *get_my_ip(const netdevice_t *device) {
	return string_to_ip_addr("192.168.1.116");
}

const int get_my_ip_info(ipv4_info_t *info) {
	IP_COPY(info->my_ip_addr, get_my_ip(NULL));
	IP_COPY(info->gateway_d, string_to_ip_addr("192.168.1.1"));
	IP_COPY(info->dns_server, string_to_ip_addr("192.168.1.10"));
	IP_COPY(info->subnet, string_to_ip_addr("192.168.1.0"));
	info->subnet_mask = 24;
	return 0;
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
const char *ip_addr_to_string(const byte *ip_addr, char *buf) {
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

/**
 * Calculate the checksum defined in RFC 791.
 * The checksum field is the 16-bit ones' complement of
 * the ones' complement sum of all 16-bit words in the
 * header. For purposes of computing the checksum,
 * the value of the checksum field should be filled
 * with zero.
 * @param data Data to check sum
 * @param len Length of data
 * @return Two bytes result of checksum
 */
two_bytes checksum(byte *data, u_int len) {
	// Iterator of data
	uint16_t *buf = (uint16_t *)data;
	// Count down of summation
	int data_cnt = len / 2;
	/**
	 * The result, aka summation of the data, is 2 bytes.
	 * But we have to calculate the carry out to feed
	 * back. So we have to use ad data type larger than
	 * 2 bytes.
	 */
	uint32_t sum;

	/**
	 * Since it's little Endian while summation,
	 * we have to swap16()
	 */
	for (sum = 0; data_cnt > 0; data_cnt--) {
		sum += swap16(*buf++);
	}
	if ((len & 0x1) != 0) {
		sum += swap16(*((uint8_t *)buf));
	}

	/**
	 * Add the carry out of sum to sum itself,
	 * do it two times since it might still have
	 * carry out after the first time.
	 */
	sum = (sum >> 16) + (sum & 0xffff);
	sum = (sum >> 16) + (sum & 0xffff);

	// Retrun the swapped result after calculate in 2 Byte data
	return swap16((two_bytes)(~sum));
}
