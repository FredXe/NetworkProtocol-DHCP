#include "ip.h"

#include "arp.h"
#include "util.h"

netdevice_t *ip_init() {
	netdevice_t *device = arp_init();

	if (netdevice_add_protocol(device, ETH_IPV4, ip_main) != 0) {
		fprintf(stderr, ERR_COLOR "%s:%d in %s(): netdevice_add_protocol() error\n" NONE, __FILE__,
				__LINE__, __func__);
		return IP_ERROR_NULL;
	}

	return device;
}

void ip_main(netdevice_t *device, const byte *packet, u_int length) {}