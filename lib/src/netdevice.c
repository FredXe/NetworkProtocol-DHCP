#include "netdevice.h"

#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>

#include "util.h"

const byte ETH_BROADCAST_ADDR[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const byte ETH_NULL_ADDR[] = {0, 0, 0, 0, 0, 0};

/**
 * Check if the Ethertype's protocol is
 * inside the device
 * @param device Device to check
 * @param eth_type Target Ethertype
 * @return 1 if found, 0 if not found
 */
int netdevice_chk_proto_list(const netdevice_t *device, const two_bytes eth_type) {
	protocol_t *proto_it = device->proto_list;	 // Protocol Iterator

	while (proto_it != NULL) {
		// Return 1 if it has inside the protocol list
		if (proto_it->eth_type == eth_type) {
			return 1;
		}
		proto_it = proto_it->next;
	}

	return 0;
}

/**
 * Capture handle of netdevice, resolve the Ethernet header
 * and passing payload to upper matching protocol.
 * @param device_u_char	netdevice_t in u_char form
 * @param header Pcap packet header
 * @param eth_frame Ethernet frame
 */
static void _capture(u_char *device_u_char, const pcap_pkthdr_t *header, const byte *eth_frame) {
	/**
	 * Cast netdevice_u_char with netdevice_t from
	 * the user that pcap_dispatch() registered
	 */
	netdevice_t *netdevice = (netdevice_t *)device_u_char;

	const eth_hdr_t *eth_hdr = (eth_hdr_t *)eth_frame;	   // Point out the Ethernet header
	const byte *payload = eth_frame + sizeof(eth_hdr_t);   // Point out the payload

	int frame_len = header->caplen;					   // Length of frame
	int payload_len = frame_len - sizeof(eth_hdr_t);   // Length of Payload

#if (DEBUG_FRAME_HDR == 1)
	char src_addr[ETH_BUF_LEN], dst_addr[ETH_BUF_LEN];

	// Print Ethernet header
	eth_addr_to_string(eth_hdr->eth_src, src_addr);
	eth_addr_to_string(eth_hdr->eth_dst, dst_addr);
	printf(ETH_2_DEBUG_COLOR "ETH revceive" ETH_DEBUG_COLOR " %s" NONE "=>" ETH_DEBUG_COLOR
							 "%s" NONE " (Type=%.04x/Len=%d)\n",
		   src_addr, dst_addr, swap16(eth_hdr->eth_type), frame_len);
#endif

#if (DEBUG_FRAME_DUMP == 1)
	print_data(eth_frame, frame_len);
#endif
	/**
	 * Go through the protocol list to
	 * find the matching protocol
	 */
	protocol_t *tmp_protocol = netdevice->proto_list;	// Iterator of protocol list
	while (tmp_protocol != NULL) {
		if (eth_hdr->eth_type == tmp_protocol->eth_type) {
			tmp_protocol->callback(netdevice, payload, payload_len);
			break;
		}
		tmp_protocol = tmp_protocol->next;
	}

	return;
}

/**
 * Get device from pcap_findalldevs(),
 * then select one of it.
 * @param dev_sel_no '0' - select from terminal.
 * 'non0' - select directly from parameter
 * @param dev_name Device name
 * @return 0 if success, dev_name will be filled
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
		fprintf(stderr, ERR_COLOR "%s:%d in %s() pcap_findalldevs(): %s\n" NONE, __FILE__, __LINE__,
				__func__, errbuf);
		goto err_out;
	}

	/**
	 * Since pcap_findalldevs() returns 0
	 * even if there's no device found,
	 * we have to return NETDEVICE_ERROR
	 */
	if (all_dev == NULL) {
		fprintf(stderr, ERR_COLOR "%s:%d in %s() There's no interface found...\n" NONE, __FILE__,
				__LINE__, __func__);
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
			fprintf(stderr, ERR_COLOR "%s:%d in %s(): scanf(): reading stdin failed\n" NONE,
					__FILE__, __LINE__, __func__);
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
		fprintf(stderr, ERR_COLOR "%s:%d in %s(): selected device out of range\n" NONE, __FILE__,
				__LINE__, __func__);
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
netdevice_t *netdevice_open(char *device_name, char *errbuf) {
	// Allocate space for device
	netdevice_t *device = (netdevice_t *)calloc(1, sizeof(netdevice_t));

	// Init protocol list by point it into NULL
	device->proto_list = NULL;
	strcpy(device->device_name, device_name);

	/**
	 * Open a pcap capture handle by pcap_open_live(),
	 * free resources and return NETDEVICE_ERROR_NULL
	 * if open failure
	 */
	if ((device->capture_handle = pcap_open_live(device_name, MTU, PCAP_OPENFLAG_PROMISCUOUS,
												 CAP_TIMEOUT, errbuf)) == NULL) {
		fprintf(stderr, ERR_COLOR "%s:%d in %s(): pcap_open_live(): %s\n" NONE, __FILE__, __LINE__,
				__func__, errbuf);
		goto err_out;
	}

	/**
	 * Set the capture device into non-blocking mode
	 */
	if (pcap_setnonblock(device->capture_handle, 1, errbuf) == PCAP_ERROR) {
		fprintf(stderr, ERR_COLOR "%s:%d in %s(): pcap_setnonblock(): %s\n" NONE, __FILE__,
				__LINE__, __func__, errbuf);
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
 * API for upper layer to sign up the protocol's
 * Ethertype and the callback function
 * @param netdevice Specify the netdevice
 * @param eth_type Ethertype of new protocol
 * @param callback Callback function's pointer
 * @return 0 on seccess
 */
int netdevice_add_protocol(netdevice_t *netdevice, const two_bytes eth_type,
						   netdevice_handler callback) {
	// Allocate memory for new protocol node
	protocol_t *new_protocol = (protocol_t *)calloc(1, sizeof(protocol_t));

	// Mapping member with arguments
	new_protocol->eth_type = eth_type;
	new_protocol->callback = callback;
	new_protocol->netdevice = netdevice;

	// Insert new protocol to the dead of the list
	new_protocol->next = netdevice->proto_list;
	netdevice->proto_list = new_protocol;

	return 0;
}

/**
 * Send a Ethernet frame out using pcap_sendpacket()
 * @param device To specify the pcap capture handle
 * @param eth_hdr Ethernet header
 * @param payload Ethernet payload
 * @param payload_len Length of payload
 * @return 0 on seccuss, NETDEVICE_ERROR on error
 */
int netdevice_xmit(const netdevice_t *device, const eth_hdr_t *eth_hdr, const byte *payload,
				   const u_int payload_len) {
	/**
	 * Return NETDEVICE_ERROR if length of
	 * payload exceed MTU
	 */
	if (payload_len > MTU) {
		fprintf(stderr, ERR_COLOR "%s:%d in %s(): length of payload exceed MTU\n" NONE, __FILE__,
				__LINE__, __func__);
		return NETDEVICE_ERROR;
	}

	const int ETH_HDR_LEN = sizeof(eth_hdr_t);	 // Const Ethernet header length
	int frame_len = ETH_HDR_LEN + payload_len;	 // Length of whole frame
	// Ethernet Frame buffer with size greater than MIN_ETH_LEN
	byte buf[MAX(MIN_ETH_LEN, frame_len)];

	/**
	 * Build the Ethernet frame into buf
	 */
	memcpy(buf, eth_hdr, ETH_HDR_LEN);				   // Add header
	memcpy(buf + ETH_HDR_LEN, payload, payload_len);   // Add payload

	// Since frame_len < 60, we need to fill the leftover into 0;
	if (frame_len < MIN_ETH_LEN) {
		memset(buf + frame_len, 0, MIN_ETH_LEN - frame_len);
		// Now, frame_len is MIN_ETH_LEN = 60
		frame_len = 60;
	}

#if (DEBUG_FRAME_HDR == 1)
	char src_addr[ETH_BUF_LEN], dst_addr[ETH_BUF_LEN];

	// Print Ethernet header
	eth_addr_to_string(eth_hdr->eth_src, src_addr);
	eth_addr_to_string(eth_hdr->eth_dst, dst_addr);
	printf(ETH_2_DEBUG_COLOR "ETH send" ETH_DEBUG_COLOR " %s" NONE "=>" ETH_DEBUG_COLOR "%s" NONE
							 " (Type=%.04x/Len=%d)\n",
		   src_addr, dst_addr, swap16(eth_hdr->eth_type), frame_len);
#endif

	/**
	 * Send packet with pcap_sendpacket(),
	 * return NETDEVICE_ERROR on error
	 */
	if (pcap_sendpacket(device->capture_handle, buf, frame_len) == PCAP_ERROR) {
		fprintf(stderr, ERR_COLOR "%s:%d in %s(): pcap_sendpacket(): %s\n" NONE, __FILE__, __LINE__,
				__func__, pcap_geterr(device->capture_handle));
		return NETDEVICE_ERROR;
	}

	return 0;
}

/**
 * Process all the packets in one buffer using pcap_dispatch(),
 * and register the callback function of netdevice
 * @param netdevice Netdevice that capture packets from
 * @return The number of packets processed on seccess;
 * NETDEVICE_ERROR on failure
 */
int netdevice_rx(netdevice_t *netdevice) {
	// Packet count that pcap_dispatch() returns
	int pkt_cnt = 0;

	/**
	 * Set cnt argument to let pcap_dispatch() to
	 * process all the packets in one buffer
	 */
	pkt_cnt = pcap_dispatch(netdevice->capture_handle, -1, _capture, (u_char *)netdevice);

	/**
	 * Return NETDEVICE_ERROR if there's error
	 * and print it to stderr
	 */
	if (pkt_cnt == PCAP_ERROR) {
		fprintf(stderr, ERR_COLOR "%s:%d in %s(): pcap_dispatch(): %s\n" NONE, __FILE__, __LINE__,
				__func__, pcap_geterr(netdevice->capture_handle));
		return NETDEVICE_ERROR;
	} else if (pkt_cnt == PCAP_ERROR_BREAK) {
		fprintf(stderr,
				ERR_COLOR "%s:%d in %s(): pcap_dispatch(): the loop terminated due to a call to "
						  "pcap_breakloop() before any packets were processed\n " NONE,
				__FILE__, __LINE__, __func__);
		return NETDEVICE_ERROR;
	}

	return pkt_cnt;
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
 * Get the MAC address by looking up
 * '/sys/class/net/(dev)/address'
 * @param device Specify the interface
 * @return Host MAC address on success,
 * NETDEVICE_ERROR_NULL on error
 */
const byte *netdevice_get_my_mac(const netdevice_t *device) {

	char addr_file_name[256] = "/sys/class/net/";	// MAC address's file name on system

	// Append device name to file name
	strcat(addr_file_name, device->device_name);
	strcat(addr_file_name, "/address");

	char MAC_addr_str[18];	 // Buffer for the file reading

	// Open the file with read mode
	FILE *addr_file = fopen(addr_file_name, "r");

	// Return NETDEVICE_ERROR_NULL is fopen() failed
	if (addr_file == NULL) {
		fprintf(stderr, ERR_COLOR "%s:%d in %s(): fopen(): error on open file\n" NONE, __FILE__,
				__LINE__, __func__);
		goto err_out;
	}

	// Read the file
	if (fscanf(addr_file, "%s", MAC_addr_str) < 0) {
		fprintf(stderr, ERR_COLOR "%s:%d in %s(): fscanf(): error on read file\n" NONE, __FILE__,
				__LINE__, __func__);
		goto err_out;
	}
	fclose(addr_file);

	// Transfer string into byte array
	return string_to_eth_addr(MAC_addr_str);

err_out:
	fclose(addr_file);
	return NETDEVICE_ERROR_NULL;
}
