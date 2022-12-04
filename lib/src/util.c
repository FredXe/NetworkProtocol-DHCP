#include "util.h"

#include <stdio.h>
#include <string.h>

ip_addr_t *string_to_ip_addr(char *ip_addr_str) {
	ip_addr_t ip_addr;
	char delim[2] = ".";
	char *token = strtok(ip_addr_str, delim);
	while (token != NULL) {
		printf("%s\n", token);
		token = strtok(NULL, delim);
	}
}