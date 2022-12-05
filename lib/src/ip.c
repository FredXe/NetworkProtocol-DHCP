#include "ip.h"

#include <stdio.h>
#include <string.h>

/**
 * Convert string into byte array
 * @param ip_addr_str *.*.*.* format string
 * @return u_int8_t* point to ip_addr.
 * IP_ERROR_NULL if error
 */
u_int8_t *string_to_ip_addr(char *ip_addr_str) {
	IP_ALLOC(ip_addr);

	// cut up the word with strtok()
	char delim[2] = ".";
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
		 * and restrict it with u_int8_t form.
		 */
		if (atoi(token) <= 256) {
			ip_addr[num_of_byte] = (u_int8_t)atoi(token);
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