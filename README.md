# DHCP c program based on libpcap
## Build and run:
```bash

# Build and run
make run
```
## Usage:
```
# Select the device
{device_number}

# Send a DHCP Discover message and Request if server replied
dhcp

# Send ${N} DHCP Discover message with fake MAC
dhcp-strv {N}
```
