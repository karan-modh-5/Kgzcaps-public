# KGZCAPS - Grandstream Zero Configuration Auto Provisioning Server

**Version:** 1.1.0

KGZCAPS is a robust zero-configuration provisioning server for Grandstream IP phones.
It provides seamless automatic configuration, supports both DHCP and static IP modes, and dynamically generates configuration files tailored to each device.

---

## Features

1. **Zero Configuration Provisioning**:
   - Automatically provisions Grandstream IP phones using SIP SUBSCRIBE and NOTIFY messages.
   - Supports both dynamic (DHCP) and static IP address assignment.

2. **Dynamic Configuration File Generation**:
   - Generates XML configuration files for Grandstream IP phones.
   - Configurations are customized per device based on MAC address.

3. **Site-Based Organization**:
   - Stores configuration files and logs in site-specific directories under the `kgzcaps` folder.
   - Example folder structure:
     ```
     /kgzcaps
         ├── SiteA/
             ├── cfgEC74D7427228.xml
             ├── cfgEC74D7427229.xml
             └── assignment-details.csv
         ├── SiteB/
             └── cfgEC74D7427230.xml
     ```

4. **SIP Multicast Listener**:
   - Listens for SIP `SUBSCRIBE` packets on multicast IP `224.0.1.75` and port `5060`.

5. **Secure HTTPS Configuration Delivery**:
   - Delivers configuration files over HTTPS (TLS 1.2).

6. **Interactive and Command-Line Options**:
   - Interactive prompts for IP addresses, site names, and other parameters.
   - Command-line arguments for automation:
     - `-u`: IPPBX IP Address
     - `-p`: SIP Authentication Password
     - `-s`: Starting IP Address
     - `-n`: Subnet Mask
     - `-g`: Gateway IP Address
     - `-a`: Starting SIP User ID
     - `-d`: DNS IP Address
     - `-i`: IP Phone Mode (1: DHCP, 2: Static)
     - `-V`: Enable Verbose Mode

---

## Requirements

- **Python 3.7 or Higher**
- **Dependencies**:
  - `ssl`, `socket`, `struct` (for network communication and HTTPS server)
  - `argparse`, `ipaddress` (for input validation)
- **TLS Certificates**:
  - Place your `tls_cert.pem` and `tls_key.pem` files in the script "kgzcaps" directory.

---

## Installation

1. Clone or download this repository.
2. Place the required TLS certificate (`tls_cert.pem`) and key (`tls_key.pem`) in the script directory.
3. Run the script:
   ```bash
   python zero_config_provider.py
   ```

---

## Usage

### Interactive Mode
Run the script and follow the prompts to provide configuration details:
1. Choose a network interface.
2. Enter the site name.
3. Provide the IPPBX IP, SIP user ID, authentication password, and other required parameters.

### Command-Line Mode
Pass arguments to automate the setup:
```bash
python zero_config_provider.py -u 192.168.1.1 -p secret -s 192.168.1.100 -a 400 -i 2 -n 255.255.255.0 -g 192.168.1.1 -d 8.8.8.8
```

---

## Example Workflow

1. **Start the Script**:
   ```bash
   python zero_config_provider.py
   ```
2. **Reboot an IP Phone**:
   - The phone sends a `SUBSCRIBE` request to `224.0.1.75`.
3. **Provisioning**:
   - KGZCAPS assigns an extension or static IP to the phone.
   - The phone fetches its configuration file via HTTPS.

---

## Troubleshooting

1. **File Not Found (404)**:
   - Ensure the MAC address in the requested URL matches the configuration file name.
   - Verify the file exists in the correct site folder.

2. **Certificate Errors**:
   - Confirm `TLS_CERT` and `TLS_KEY` paths are correct and files are present.

3. **SIP Server Not Responding**:
   - Ensure the interface IP is set correctly.
   - Verify multicast support on your network.

---
