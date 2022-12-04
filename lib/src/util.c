#include "util.h"

#include "ip.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

/**
 *	Convert string into byte array
 *	@param ip_addr_str *.*.*.* format string
 */
u_int8_t *string_to_ip_addr(char *ip_addr_str) {
	IP_ALLOC(ip_addr);
	char delim[2] = ".";
	char *token = strtok(ip_addr_str, delim);
	int num_of_byte = 0;

	while (token != NULL) {
		/*
		 *	Convert it using atoi method
		 *	when its valid,
		 *	and restrict it with u_int8_t form.
		 */
		if (atoi(token) < 256) {
			ip_addr[num_of_byte] = (u_int8_t)atoi(token);
		}

		token = strtok(NULL, delim);
		num_of_byte++;

		/*
		 *	Return NULL if input string
		 *	is too long
		 */
		if (num_of_byte > 4) {
			return NULL;
		}
	}

	return ip_addr;
}