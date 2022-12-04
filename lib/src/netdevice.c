#include "netdevice.h"

#include <stdio.h>
#include <string.h>

u_int8_t *string_to_eth_addr(char *eth_addr_str) {
	if ((int)strlen(eth_addr_str) > 17) {
		fprintf(stderr, "%s:%d in %s(): length of eth_addr_str out of range\n", __FILE__, __LINE__,
				__func__);
		return NULL;
	}

	ETH_ALLOC(eth_addr);
	char delim[2] = ":";
	char *token = strtok(eth_addr_str, delim);
	int num_of_byte = 0;
	while (token != NULL) {
		/*
		 *	Return NULL if input string
		 *	is too long
		 */
		if (num_of_byte >= ETH_ADDR_LEN) {
			fprintf(stderr, "%s:%d in %s(): length of eth_addr_str out of range\n", __FILE__,
					__LINE__, __func__);
			goto err_return;
		}

		/*
		 *	Convert it using strtol in base hex,
		 *	and cast it with u_int8_t form.
		 */
		eth_addr[num_of_byte] = (u_int8_t)strtol(token, NULL, 16);

		token = strtok(NULL, delim);
		num_of_byte++;
	}

	return eth_addr;

err_return:
	free(eth_addr);
	return NULL;
}