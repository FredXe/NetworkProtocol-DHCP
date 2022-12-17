# DHCP c program based on libpcap
## Usage:
```bash

# Build and run
make run

# Select the device
{device_number}

# Send a DHCP Discover message and Request if server replied
dhcp

# Send ${N} DHCP Discover message with fake MAC
dhcp-strv {N}
```
