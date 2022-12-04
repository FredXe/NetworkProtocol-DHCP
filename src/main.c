#include "util.h"
#include <pcap/pcap.h>
#include <stdio.h>

int main() {
	char str[20] = "192.168.1.1";
	ip_addr_t *ip = string_to_ip_addr(str);
	ip = ip;
}