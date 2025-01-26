# KGZCAPS - Grandstream Zero Configuration Auto Provisioning Server

**Version:** 1.1.3

KGZCAPS is an advanced provisioning server for Grandstream IP phones.
With the addition of a built-in DHCP server mode, it provides end-to-end automation for configuring IP phones in both static and dynamic IP environments.

---

## Features

1. **Zero Configuration Provisioning**:
   - Automatically provisions Grandstream IP phones using SIP SUBSCRIBE and NOTIFY messages.
   - Supports both dynamic (DHCP) and static IP address assignment.

2. **Dynamic Configuration File Generation**:
   - Generates XML configuration files tailored to each IP phone based on MAC address.

3. **Site-Based Organization**:
   - Organizes configuration files and logs in site-specific directories under the `kgzcaps` folder.
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

4. **Integrated DHCP Server** (New):
   - Assigns IP addresses to Grandstream IP phones dynamically using the built-in DHCP server.
   - Filters non-Grandstream devices based on OUI.

5. **SIP Multicast Listener**:
   - Listens for SIP `SUBSCRIBE` packets on multicast IP `224.0.1.75` and port `5060`.

6. **Secure HTTPS Configuration Delivery**:
   - Delivers configuration files over HTTPS (TLS 1.2).

7. **Interactive and Command-Line Options**:
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
     - `-D`: Enable DHCP Server mode
     - `-DS`: Starting DHCP IP Address
     - `-DE`: End DHCP IP Address
     - `-V`: Enable Verbose Mode

---

### New Features

1. **Dynamic P-CODE Configuration**:
   - Allows you to dynamically add or modify P-CODES directly from the script interface.
   - P-CODEs are customizable and can be extended per your requirements.

2. **Provisioning from `config.csv`**:
   - Reads from a `config.csv` file in the `kgzcaps` folder.
   - Supports:
     - **Normal Mode**: Requires 2 columns (`MAC Address`, `Account Number`).
     - **Static Mode**: Requires 3 columns (`MAC Address`, `Account Number`, `IP Address`).
   - Automatically applies these configurations during provisioning.

---

## Requirements

- **Python 3.7 or Higher**
- **Dependencies**:
  - `ssl`, `socket`, `struct` (for network communication and HTTPS server)
  - `argparse`, `ipaddress` (for input validation)
- **TLS Certificates**:
  - Place your `tls_cert.pem` and `tls_key.pem` files in the `kgzcaps` directory.

---

## Installation

1. Clone or download this repository.
2. Place the required TLS certificate (`tls_cert.pem`) and key (`tls_key.pem`) in the `kgzcaps` folder.
3. Run the script:
   ```bash
   python kgzcaps.py
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
python kgzcaps.py -u 192.168.1.1 -p secret -s 192.168.1.100 -a 400 -i 2 -n 255.255.255.0 -g 192.168.1.1 -d 8.8.8.8 -D -DS 192.168.1.101 -DE 192.168.1.200
```

---

## Configuration via `config.csv`

### Normal Mode (DHCP)
The `config.csv` should contain two columns:
```
MAC Address,Account Number
EC74D7427228,400
EC74D7427229,401
```

### Static Mode
The `config.csv` should contain three columns:
```
MAC Address,Account Number,IP Address
EC74D7427228,400,192.168.1.100
EC74D7427229,401,192.168.1.101
```

---

## Example Workflow

1. **Start the Script**:
   ```bash
   python kgzcaps.py
   ```
2. **Reboot an IP Phone**:
   - The phone sends a `SUBSCRIBE` request to `224.0.1.75`.
3. **Provisioning**:
   - KGZCAPS assigns an extension or static IP to the phone.
   - The phone fetches its configuration file via HTTPS.

4. **DHCP Server Mode**:
   - Enable DHCP server mode with `-D` to provide IP addresses dynamically.
   - The server listens on port 67 for DHCP DISCOVER/REQUEST packets.

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

4. **DHCP Server Not Working**:
   - Check if the DHCP port (67) is in use by another service.
   - Ensure the server's IP is within the network segment.

---

## Download
[Kgzcaps.py](https://karan-modh.tech/download/kgzcaps.py)

---
