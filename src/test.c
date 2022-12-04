#include "util.h"
#include <pcap/pcap.h>
#include <stdio.h>

int main() {
	char str[12] = "192.168.1.1";
	u_int8_t *ip;
	ip = string_to_ip_addr(str);
	free(ip);

	printf("test\n");
	return 0;
}