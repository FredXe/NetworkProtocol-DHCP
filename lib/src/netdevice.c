#include "netdevice.h"

#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>

/**
 * Get device from pcap_findalldevs(),
 * than select one of it.
 * @param dev_sel_no '0' - select from terminal.
 * 'non0' - select directly from parameter
 * @param dev_name
 * @return 0 if success.
 * NETDEVICE_ERROR if error
 */
int netdevice_getdevice(const int define_n, char *dev_name) {
	pcap_if_t *all_dev;

	/**
	 * Find all devices
	 * , return NETDEVICE_ERROR if error to find device
	 */
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&all_dev, errbuf) == PCAP_ERROR) {
		fprintf(stderr, "%s:%d in %s()\n pcap_findalldevs(): %s\n", __FILE__, __LINE__, __func__,
				errbuf);
		goto err_out;
	}

	/**
	 * Since pcap_findalldevs() returns 0
	 * even if there's no device found,
	 * we have to return NETDEVICE_ERROR
	 */
	if (all_dev == NULL) {
		fprintf(stderr, "There's no interface found...\n");
		goto err_out;
	}

	int dev_cnt = 0;		  // device count
	int dev_sel = define_n;	  // device selected

	/**
	 * Go through device list.
	 * Print device list if no device select yet
	 */
	for (pcap_if_t *d_tmp = all_dev; d_tmp != NULL; d_tmp = d_tmp->next) {
		dev_cnt++;
		if (dev_sel == 0)
			printf("%d. %s\n", dev_cnt, d_tmp->name);
	}

	/**
	 * Get device which user select from stdin.
	 * Return NETDEVICE_ERROR if scanf() read failed
	 */
	if (dev_sel == 0) {
		printf("select the device (1-%d): ", dev_cnt);
		if (scanf("%d", &dev_sel) != 1) {
			fprintf(stderr, "%s:%d in %s(): scanf(): reading stdin failed\n", __FILE__, __LINE__,
					__func__);
			goto err_out;
		}
	}

	/**
	 * Go through the device list
	 * using dev_sel to countdown.
	 * Block device selected is valid.
	 */
	if (dev_sel <= dev_cnt && 0 < dev_sel) {
		pcap_if_t *d_tmp = all_dev;
		for (; dev_sel - 1 > 0; d_tmp = d_tmp->next, dev_sel--)
			;
		strcpy(dev_name, d_tmp->name);
	}
	/**
	 * Block device selected is invalid.
	 * Return NETDEVICE_ERROR if device selected
	 * is out of range of device list
	 */
	else {
		fprintf(stderr, "%s:%d in %s(): selected device out of range\n", __FILE__, __LINE__,
				__func__);
		goto err_out;
	}

	pcap_freealldevs(all_dev);
	return 0;

/**
 * Label where exit with error.
 * Free the devices and return error code
 */
err_out:
	pcap_freealldevs(all_dev);
	return NETDEVICE_ERROR;
}

/**
 * Open a pcap capture interface with promiscuous mode,
 * and set it into non-blocking mode
 * @param device_name device name select
 * @param errbuf errbuf will be fill if there's error
 * @return Netdevice, NETDEVICE_ERROR_NULL if error
 */
netdevice_t *netdevice_open(const char *device_name, char *errbuf) {
	netdevice_t *device = (netdevice_t *)calloc(1, sizeof(netdevice_t));
	device->proto_list = NULL;

	/**
	 * Open a pcap capture handle by pcap_open_live(),
	 * free resources and return NETDEVICE_ERROR_NULL
	 * if open failure
	 */
	if ((device->capture_handle = pcap_open_live(device_name, MTU, PCAP_OPENFLAG_PROMISCUOUS,
												 CAP_TIMEOUT, errbuf)) == NULL) {
		fprintf(stderr, "%s:%d in %s(): pcap_open_live(): open pcap capture handle failed\n",
				__FILE__, __LINE__, __func__);
		goto err_out;
	}

	/**
	 * Set the capture device into non-blocking mode
	 */
	if (pcap_setnonblock(device->capture_handle, 1, errbuf) == PCAP_ERROR) {
		fprintf(stderr, "%s:%d in %s(): pcap_setnonblock(): set non-blocking mode failed\n",
				__FILE__, __LINE__, __func__);
		goto err_out;
	}

	return device;

/**
 * Label for exit with error.
 * Free resources and return NETDEVICE_ERROR_NULL
 */
err_out:
	netdevice_close(device);
	return NETDEVICE_ERROR_NULL;
}

/**
 * Free all the resources of netdevice
 */
void netdevice_close(netdevice_t *device) {
	protocol_t *protocol;		// Protocol_t* to go through protocol list
	protocol_t *tmp_protocol;	// Protocol_t going to be free

	/**
	 * Free the whole protocol list
	 */
	for (protocol = device->proto_list; protocol != NULL;) {
		tmp_protocol = protocol;
		protocol = protocol->next;
		free(tmp_protocol);
	}

	// close capture handle in device
	pcap_close(device->capture_handle);
	// free device itself
	free(device);

	return;
}

/**
 * Convert string into byte array
 * @param eth_addr_str **:**:**:**:**:** format string
 * @return byte* point to eth_addr.
 * NETDEVICE_ERROR_NULL if error
 */
byte *string_to_eth_addr(char *eth_addr_str) {
	/**
	 * Return NETDEVICE_ERROR_NULL if length of MAC address is too long
	 */
	if ((int)strlen(eth_addr_str) > 17) {
		fprintf(stderr, "%s:%d in %s(): length of eth_addr_str out of range\n", __FILE__, __LINE__,
				__func__);
		return NETDEVICE_ERROR_NULL;
	}

	ETH_ALLOC(eth_addr);

	// Cut up the word with stortok()
	char delim[2] = ":";
	char *token = strtok(eth_addr_str, delim);

	int num_of_byte = 0;
	while (token != NULL) {
		/**
		 * Return NULL if input string
		 * is too long
		 */
		if (num_of_byte >= ETH_ADDR_LEN) {
			fprintf(stderr, "%s:%d in %s(): length of eth_addr_str out of range\n", __FILE__,
					__LINE__, __func__);
			goto err_out;
		}

		/**
		 * Convert it using strtol in base hex,
		 * and cast it with byte form.
		 */
		eth_addr[num_of_byte] = (byte)strtol(token, NULL, 16);

		token = strtok(NULL, delim);
		num_of_byte++;
	}

	return eth_addr;

/**
 * Label for error exit.
 * Free allocated var and return NETDEVICE_ERROR_NULL
 */
err_out:
	free(eth_addr);
	return NETDEVICE_ERROR_NULL;
}