#include "ip.h"

#include <stdio.h>
#include <string.h>

byte *ip_get_my_ip(netdevice_t *device) {
	return string_to_ip_addr("192.168.1.116");
}

/**
 * Convert string into byte array
 * @param ip_addr_str *.*.*.* format string
 * @return byte* point to ip_addr.
 * IP_ERROR_NULL if error
 */
byte *string_to_ip_addr(const char *ip_addr_str_in) {
	IP_ALLOC(ip_addr);

	/**
	 * Since we're using strtok() later,
	 * we have to store the input const char[]
	 * into a char[].
	 */
	char ip_addr_str[16];
	strcpy(ip_addr_str, ip_addr_str_in);

	// Cut up the word with strtok()
	const char delim[2] = ".";
	char *token = strtok(ip_addr_str, delim);

	int num_of_byte = 0;   // count the number of bytes for validate

	while (token != NULL) {
		/**
		 * Return NULL if input string
		 * is too long
		 */
		if (num_of_byte >= IP_ADDR_LEN) {
			fprintf(stderr, "%s:%d in %s(): length of ip_addr_str out of range\n", __FILE__,
					__LINE__, __func__);
			goto err_out;
		}

		/**
		 * Convert it using atoi method
		 * when its valid,
		 * and restrict it with byte form.
		 */
		if (atoi(token) <= 256) {
			ip_addr[num_of_byte] = (byte)atoi(token);
		} else {
			fprintf(stderr, "%s:%d in %s(): ip addr should be <= 256\n", __FILE__, __LINE__,
					__func__);
			goto err_out;
		}
		token = strtok(NULL, delim);
		num_of_byte++;
	}

	return ip_addr;

/**
 * Label for error exit.
 * Free allocated var and return IP_ERROR_NULL
 */
err_out:
	free(ip_addr);
	return IP_ERROR_NULL;
}