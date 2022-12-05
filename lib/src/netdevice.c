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
 * Convert string into byte array
 * @param eth_addr_str **:**:**:**:**:** format string
 * @return u_int8_t* point to eth_addr.
 * NULL if error
 */
u_int8_t *string_to_eth_addr(char *eth_addr_str) {
	if ((int)strlen(eth_addr_str) > 17) {
		fprintf(stderr, "%s:%d in %s(): length of eth_addr_str out of range\n", __FILE__, __LINE__,
				__func__);
		return NULL;
	}

	ETH_ALLOC(eth_addr);

	// cut up the word with stortok()
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
		 * and cast it with u_int8_t form.
		 */
		eth_addr[num_of_byte] = (u_int8_t)strtol(token, NULL, 16);

		token = strtok(NULL, delim);
		num_of_byte++;
	}

	return eth_addr;

/**
 * Label for error exit.
 * Free allocated var and return NULL
 */
err_out:
	free(eth_addr);
	return NULL;
}