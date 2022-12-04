#include "ip.h"

#include <stdio.h>
#include <string.h>

u_int8_t *string_to_ip_addr(char *ip_addr_str) {
	IP_ALLOC(ip_addr);
	char delim[2] = ".";
	char *token = strtok(ip_addr_str, delim);
	int num_of_byte = 0;

	while (token != NULL) {
		/*
		 *	Return NULL if input string
		 *	is too long
		 */
		if (num_of_byte >= IP_ADDR_LEN) {
			fprintf(stderr, "%s:%d in %s(): length of ip_addr_str out of range\n", __FILE__,
					__LINE__, __func__);
			goto err_return;
		}

		/*
		 *	Convert it using atoi method
		 *	when its valid,
		 *	and restrict it with u_int8_t form.
		 */
		if (atoi(token) <= 256) {
			ip_addr[num_of_byte] = (u_int8_t)atoi(token);
		} else {
			fprintf(stderr, "%s:%d in %s(): ip addr should be <= 256\n", __FILE__, __LINE__,
					__func__);
			goto err_return;
		}
		token = strtok(NULL, delim);
		num_of_byte++;
	}

	return ip_addr;

err_return:
	free(ip_addr);
	return NULL;
}