import csv
import argparse
import sys
import re
import ipaddress
import os
import csv
import shutil
import math
import time
import ipaddress
import socket
import struct
import ssl
from http.server import HTTPServer, SimpleHTTPRequestHandler
from threading import Thread
try:
    from OpenSSL import crypto
except ValueError:
    print("pyOpenSSL is not installed please run: pip install pyOpenSSL")

version = "1.1.6" # Version of the script

# Variables for storing input parameters
IPPBX_IP = ""
loading_time = 0.01 # Time delay for the loading effect
INTERFACE_IP = ""  
extension_counter = ""  # Starting extension number
start_ip = ""
subnet_mask = ""
gateway_ip = ""
dns_ip = ""
ip_mode = ""
SIP_AUTH_PASS = ""
provisioned_devices = {}
site_folder_map = {}  # Global mapping of site names to folder paths
# Multicast and SIP Configuration
MULTICAST_GROUP = "224.0.1.75"
MULTICAST_PORT = 5060
RESPONSE_PORT = 6060

# HTTPS Configuration
HTTPS_PORT = 8089

# Paths to TLS Certificate and Key
TLS_CERT = "kgzcaps/tls_cert.pem"  # Path to your certificate
TLS_KEY = "kgzcaps/tls_key.pem"    # Path to your private key

# DHCP Function
leases = {}
dhcpd_start_ip = ""
dhcpd_end_ip = ""

ALLOWED_OUIS = [
    "00:0B:82",  # Example Grandstream OUI
    "00:0B:46",
    "AC:CF:23",
    "C0:74:AD",
    "EC:74:D7",
]

additional_cfg = {
'102':'2',
'64':'TZT-5:30',
'122':'0',
'414':'0',
'52':'2',
'104':'2',
'2348':'1',
'2397':'1',
'26073':'0',
'78':'0',
'8350':'1',
'8351':'1',
'8446':'0',
'33':'*97',
'271':'1',
'1558':'26'
}

# Function to check if input is numeric
def is_numeric(input_str):
    return re.match(r"^\d{2,}$", input_str) is not None

# Function to validate if the input is a valid IP address
def is_valid_ip(ip):
    ip_pattern = re.compile(r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                            r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                            r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                            r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$") # Regular expression for IPv4
    return bool(ip_pattern.match(ip))  # Return True if valid, False otherwise    

# Function to validate subnet mask input
def is_valid_subnet_mask(subnet_mask):
    try:
        subnet = ipaddress.IPv4Network(f"0.0.0.0/{subnet_mask}", strict=False)  # Parse subnet mask
        return not subnet.with_prefixlen.endswith('/0')  # Ensure the subnet is valid
    except ValueError:
        return False

# Argument parser setup for command-line inputs
parser = argparse.ArgumentParser(description="grandstream zero configuration auto provisioning server")
parser.add_argument("-v", action="store_true", help="Print version info")
parser.add_argument("-p", help="SIP Autentication Password")
parser.add_argument("-u", help="IPPBX IP Address")
parser.add_argument("-s", help="Starting IP Address")
parser.add_argument("-n", help="Subnet Mask")
parser.add_argument("-g", help="Gateway IP Address")
parser.add_argument("-a", help="Starting Account")
parser.add_argument("-d", help="DNS IP Address")
parser.add_argument("-i", type=int, help="IP Phones mode")
parser.add_argument("-P", "--PCODE", action="store_true", help="Change P-CODEs")
parser.add_argument("-D", "--dhcpd", action="store_true", help="Enable DHCP Server mode")
parser.add_argument("-DS", help="Starting DHCP IP Address")
parser.add_argument("-DE", help="End DHCP IP Address")
parser.add_argument("-V", "--verbose", action="store_true", help="Enable verbose mode")

# Parse the command-line arguments
args = parser.parse_args()

# Handle version argument
if args.v:
    print("\nkgzcaps version: {}".format(version))
    sys.exit(0)

if args.p:
    SIP_AUTH_PASS = args.p

if args.u:
    if is_valid_ip(args.u):
        IPPBX_IP = args.u

if args.s:
    if is_valid_ip(args.s):
        start_ip = args.s

if args.n:
    try:
        if int(args.n) <= 32:
            print("Invalid IP address. Please enter a valid Subnet Mask.")
    except:
        if is_valid_subnet_mask(args.n):
            subnet_mask = args.n

if args.g:
    if is_valid_ip(args.g):
        gateway_ip = args.g

if args.a:
    if is_numeric(args.a):
        extension_counter = int(args.a)

if args.d:
    if is_valid_ip(args.d):
        dns_ip = args.d

if args.i:
    if args.i in (1, 2):
        ip_mode = args.i

if args.DS:
    if is_valid_ip(args.DS):
        dhcpd_start_ip = args.DS
        
if args.DE:
    if is_valid_ip(args.DE):
        dhcpd_end_ip = args.DE
        
# Verbose flag
VERBOSE_MODE = args.verbose

def log_verbose(message):
    """Print verbose messages if verbose mode is enabled."""
    if VERBOSE_MODE:
        print(f"[VERBOSE] {message}")

def generate_tls_cert(cert_file, key_file):
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        print("tls cert and tls key files are not found in kgzcaps folder.")
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        cert = crypto.X509()
        cert.get_subject().CN = "kgzcaps"
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)  # 10 years
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, 'sha256')
        
        with open(cert_file, "wb") as cert_out:
            cert_out.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        with open(key_file, "wb") as key_out:
            key_out.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

# Function to display a progress bar
def progress_bar(progress, total):
    percent = 100 * (progress / float(total))
    terminal_width, _ = shutil.get_terminal_size()
    if terminal_width > 80:
        terminal_width = 80

    bar_width = int((terminal_width - 10) * (percent / 100))
    bar = '>' * bar_width + ' ' * (terminal_width - 10 - bar_width)

    print(f"\r[{bar}] {percent:.2f}%", end="\r")

# ASCII logo used in the script
logo = [
    "                                                                                ",
    "                                                                                ",
    "        █████                                                                   ",
    "       ░░███                                                                    ",
    "        ░███ █████  ███████  █████████  ██████   ██████   ████████   █████      ",
    "        ░███░░███  ███░░███ ░█░░░░███  ███░░███ ░░░░░███ ░░███░░███ ███         ",
    "        ░██████░  ░███ ░███ ░   ███░  ░███ ░░░   ███████  ░███ ░███░░█████      ",
    "        ░███░░███ ░███ ░███   ███░   █░███  ███ ███░░███  ░███ ░███ ░░░░███     ",
    "        ████ █████░░███████  █████████░░██████ ░░████████ ░███████  ██████      ",
    "       ░░░░ ░░░░░  ░░░░░███ ░░░░░░░░░  ░░░░░░  ░░░░░░     ░███░░░  ░░░░░░       ",
    "                   ███ ░███                               ░███                  ",
    "                  ░░██████                                █████                 ",
    "                                                                                ",
    "                                                                                ",
    "================================================================================",
]

# Function to display the loading logo
def slow_print_logo(logo, delay):
    for line in logo:
        print(line)
        time.sleep(delay)  # Add delay between each line

def logo_loading():
    slow_print_logo(logo, delay=loading_time+0.01)  # Adjust delay for slower/faster printing

# Function to clear the terminal screen
def clear():
    os.system('cls' if os.name == 'nt' else 'clear')  # Clear screen for Windows ('cls') or Unix/Linux ('clear')

# Main function for running the loading effect
def loading():
    #clear()  # Clear the terminal screen
    logo_loading()  # Show the ASCII logo with a loading effect

def get_ip_addresses():
    interfaces = {}
    result = os.popen('ipconfig').read()
    
    current_interface = None
    for line in result.split('\n'):
        if "adapter" in line:
            current_interface = line.split("adapter")[1].strip(" :\r")
        elif "IPv4 Address" in line:
            if current_interface:
                ip = line.split(":")[1].strip()
                interfaces[current_interface] = ip

    return interfaces

def display_interfaces(interfaces):
    for index, (interface, ip) in enumerate(interfaces.items(), start=1):
        print(f"{index}. Interface: {interface}, IP Address: {ip}")

def choose_interface(interfaces):
    while True:
        display_interfaces(interfaces)
        try:
            choice = int(input("Choose network interface by entering the corresponding number: "))
            if 1 <= choice <= len(interfaces):
                chosen_interface = list(interfaces.items())[choice - 1]
                return chosen_interface
            else:
                print("Invalid number. Please enter a number corresponding to the listed interfaces.")
        except ValueError:
            print("Invalid input. Please enter a number.")

def get_config_file(site, TLS_CERT, TLS_KEY):
    """Get or create the folder path for a site."""
    kgzcaps = "kgzcaps"
    script_directory = os.getcwd()  # Get the current script directory
    folder_path = os.path.join(script_directory, kgzcaps, site)  # Include kgzcaps in the path
    tls_cert_path = os.path.join(script_directory, TLS_CERT)
    tls_key_path = os.path.join(script_directory, TLS_KEY)

    # Update the global mapping
    site_folder_map[site] = folder_path

    # Create the directory if it doesn't exist
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
        print(f"Folder '{folder_path}' created successfully.")
    else:
        print(f"Folder '{folder_path}' already exists.")

    generate_tls_cert(TLS_CERT, TLS_KEY)

    # Set file paths for output files
    assingment_file_name = "assingment-details.csv"
    assingment_file_path = os.path.join(folder_path, assingment_file_name)  # Path for assingment file
    
    # Open files or create them if they don't exist
    try:
        with open(assingment_file_path, "r") as file:
            print(f"Found existing '{assingment_file_name}' in the '{site}' folder.")
    except FileNotFoundError:
        with open(assingment_file_path, "w") as file:
            print(f"Created '{assingment_file_name}' in the '{site}' folder.")
    finally:
        print(f"IP Phones configuration files and assingment-details.csv file will be stored in '{site}' folder")
        return (assingment_file_path, folder_path)

def load_config_file(ip_mode):
    """Load configuration values from config.csv based on mode."""
    config_file_path = os.path.join("kgzcaps", "config.csv")
    config_data = {}

    if not os.path.exists(config_file_path):
        print(f"[INFO] No config.csv file found in 'kgzcaps'. Dynamic assignment will be used.")
        return config_data

    with open(config_file_path, mode="r") as file:
        reader = csv.reader(file)
        next(reader, None)  # Skip the header row
        for row in reader:
            # Validate columns based on mode
            if ip_mode == 1 and len(row) != 2:
                print(f"[ERROR] Invalid row for DHCP mode: {row}")
                continue
            if ip_mode == 2 and len(row) != 3:
                print(f"[ERROR] Invalid row for static mode: {row}")
                continue

            # Extract values
            mac = row[0].strip().lower()
            account = int(row[1].strip())
            ip = row[2].strip() if ip_mode == 2 else None

            # Store configuration
            config_data[mac] = {"account": account}
            if ip_mode == 2:
                config_data[mac]["ip"] = ip

    print(f"[INFO] Loaded configuration for {len(config_data)} devices from config.csv.")
    return config_data

def generate_config_file(mac_address, extension, SIP_AUTH_PASS ,ip , subnet_mask, gateway_ip, dns_ip, additional_cfg):
    """Generate configuration content dynamically."""
    cfg_start = f"""<?xml version="1.0" encoding="UTF-8" ?>
<gs_provision version="1">
    <mac>{mac_address}</mac>
    <config version="1">"""
    
    unique_cfg = {
    '2':SIP_AUTH_PASS,
    '30':IPPBX_IP,
    '35':extension,
    '270':extension,
    '36':extension,
    '34':SIP_AUTH_PASS,
    '47':IPPBX_IP
    }

    if ip_mode == 2:
        static_mode_cfg = {
        '8':'1',
        '9':ip.split('.')[0],
        '10':ip.split('.')[1],
        '11':ip.split('.')[2],
        '12':ip.split('.')[3],
        '13':subnet_mask.split('.')[0],
        '14':subnet_mask.split('.')[1],
        '15':subnet_mask.split('.')[2],
        '16':subnet_mask.split('.')[3],
        '17':gateway_ip.split('.')[0],
        '18':gateway_ip.split('.')[1],
        '19':gateway_ip.split('.')[2],
        '20':gateway_ip.split('.')[3],
        '21':dns_ip.split('.')[0],
        '22':dns_ip.split('.')[1],
        '23':dns_ip.split('.')[2],
        '24':dns_ip.split('.')[3]
        }
    
    # Add any additional options provided by the user
    cfg_addition = ""
    for key, value in unique_cfg.items(): 
        cfg_addition += f"""\n        <P{key}>{value}</P{key}>"""
    for key, value in additional_cfg.items(): 
        cfg_addition += f"""\n        <P{key}>{value}</P{key}>"""
    if ip_mode == 2:
        for key, value in static_mode_cfg.items(): 
            cfg_addition += f"""\n        <P{key}>{value}</P{key}>"""

    cfg_end = """
    </config>
</gs_provision>
"""

    return cfg_start + cfg_addition + cfg_end

def generate_from_config_file(site, SIP_AUTH_PASS , start_ip, subnet_mask, gateway_ip, dns_ip, additional_cfg):
    folder = site_folder_map.get(site)
    if not folder:
        print(f"Error: Site {site} folder not found.")
        return
    
    device_config = load_config_file(ip_mode)
    log_verbose(device_config)
    
    if ip_mode == 1:
        for mac, value in device_config.items():     
            account = value.get("account", {})
            print(mac.upper(), "-", account)
            ip = "0.0.0.0"
            config_content = generate_config_file(mac, account, SIP_AUTH_PASS, ip, subnet_mask, gateway_ip, dns_ip, additional_cfg)
            provisioned_devices[mac] = account
            file_name = os.path.join(folder, f"cfg{mac}.xml")
            with open(file_name, "w") as config_file:
                config_file.write(config_content)
            log_verbose(f"Configuration file created: {file_name}")
        
    if ip_mode == 2:
        for mac, value in device_config.items():     
            account = value.get("account", {})
            ip = value.get("ip", {})
            print(mac.upper(), "-", account, "-", ip)
            config_content = generate_config_file(mac, account, SIP_AUTH_PASS, ip , subnet_mask, gateway_ip, dns_ip, additional_cfg)
            provisioned_devices[mac] = account
            file_name = os.path.join(folder, f"cfg{mac}.xml")
            with open(file_name, "w") as config_file:
                config_file.write(config_content)
            log_verbose(f"Configuration file created: {file_name}")

def save_config_file(mac_address, extension_counter, site, SIP_AUTH_PASS ,ip , subnet_mask, gateway_ip, dns_ip, additional_cfg):
    """Save configuration file in the specific site folder."""
    folder = site_folder_map.get(site)
    if not folder:
        print(f"Error: Site {site} folder not found.")
        return
    
    file_name = os.path.join(folder, f"cfg{mac_address}.xml")
    config_content = generate_config_file(mac_address, extension_counter, SIP_AUTH_PASS, ip , subnet_mask, gateway_ip, dns_ip, additional_cfg)
    with open(file_name, "w") as config_file:
        config_file.write(config_content)
    log_verbose(f"Configuration file created: {file_name}")

# Function to send NOTIFY packet
def send_notify(addr, call_id, cseq, port, from_tag, to_tag, site):
    body_length_without_ip = 24
    ip_length = len(INTERFACE_IP)
    body_length = body_length_without_ip + ip_length
    log_verbose(f"Notify packet body length: {body_length}")
    notify_message = (
        f"NOTIFY sip:{addr[0]}:{addr[1]} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {INTERFACE_IP}:{port};branch=z9hG4bK1771679954\r\n"
        f"From: <sip:{INTERFACE_IP}:{port}>;tag={from_tag}\r\n"
        f"To: <sip:{addr[0]}:{addr[1]}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: {cseq} NOTIFY\r\n"
        f"Contact: <sip:{INTERFACE_IP}:{port}>\r\n"
        f"Content-Type: application/url\r\n"
        f"Max-Forwards: 70\r\n"
        f"User-Agent: Grandstream UCM6302V1.3A 1.0.27.10\r\n"
        f"Event: ua-profile\r\n"
        f"Content-Length: {body_length}\r\n"
        f"\r\n"
        f"https://{INTERFACE_IP}:{HTTPS_PORT}/kgzcaps/\r\n"
    )

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as notify_socket:
        notify_socket.bind((INTERFACE_IP, port))  # Bind to 6060
        notify_socket.sendto(notify_message.encode(), addr)
        log_verbose(f"Sent NOTIFY to {addr} from port {port}")

# Function to handle SIP SUBSCRIBE
def sip_server(site, SIP_AUTH_PASS, assingment_file_path ,start_ip, subnet_mask, gateway_ip, dns_ip, additional_cfg):
    """Start the SIP server to handle SUBSCRIBE requests."""
    global extension_counter
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind to all addresses on the specified port
    sock.bind(("", MULTICAST_PORT))

    # Join the multicast group on the specific interface
    group = socket.inet_aton(MULTICAST_GROUP)
    interface = socket.inet_aton(INTERFACE_IP)
    mreq = struct.pack("4s4s", group, interface)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    time.sleep(1.5)    
    log_verbose(f"SIP Server listening on {MULTICAST_GROUP}:{MULTICAST_PORT} via interface {INTERFACE_IP}")

    while True:
        data, addr = sock.recvfrom(1024)
        log_verbose(f"Received data from {addr}: {data.decode(errors='ignore')}")
        if b"SUBSCRIBE" in data:
            log_verbose(f"SUBSCRIBE detected from {addr}")

            # Parse data for required fields
            headers = data.decode(errors="ignore").split("\r\n")

            # Extract MAC address from SUBSCRIBE packet (simulate this for now)
            mac = headers[2].split(":")[2].split("MAC%3A")[1].split("@")[0]
            mac_address = mac.lower()
            log_verbose(provisioned_devices)
            if mac_address not in provisioned_devices:
                # Assign a new extension and save the configuration file
                provisioned_devices[mac_address] = extension_counter

                save_config_file(mac_address, extension_counter, site, SIP_AUTH_PASS ,str(start_ip), subnet_mask, gateway_ip, dns_ip, additional_cfg)
                
                with open(assingment_file_path, mode='a') as file:
                    if ip_mode == 1:
                        print("[LOG]", mac, "Assigned Extension", extension_counter)                        
                        file.write(f"MAC Address,{mac.strip()},Account,{extension_counter}\n")
                    if ip_mode == 2:
                        print("[LOG]", mac, "given static IP Address", start_ip, "Assined Extension", extension_counter)
                        file.write(f"MAC Address,{mac.strip()},Static IP,{start_ip},Account,{extension_counter}\n")
                        start_ip = ipaddress.IPv4Address(start_ip)
                        start_ip += 1
                extension_counter += 1

            get_branch = (headers[1]).split(";")[1].split("branch=")[1]
            call_id = next((h.split(": ")[1] for h in headers if h.startswith("Call-ID:")))
            cseq = next((h.split(": ")[1].split(" ")[0] for h in headers if h.startswith("CSeq:")), "1")
            from_header = next((h for h in headers if h.startswith("From:")), "")
            from_tag = from_header.split("tag=")[-1] if "tag=" in from_header else "default-from-tag"
            to_header = next((h for h in headers if h.startswith("To:")), "")
            to_tag = to_header.split("tag=")[-1] if "tag=" in to_header else "1609062690"

            # Send 202 Accepted from port 6060
            response = (
                "SIP/2.0 202 Accepted subscription\r\n"
                f"Via: SIP/2.0/UDP {addr[0]}:{addr[1]};branch={get_branch};rport\r\n"
                f"From: <sip:MAC%3A{mac}@{MULTICAST_GROUP}>;tag={from_tag}\r\n"
                f"To: <sip:MAC%3A{mac}@{MULTICAST_GROUP}>;tag={to_tag}\r\n"
                f"Call-ID: {call_id}\r\n"
                f"CSeq: {cseq} SUBSCRIBE\r\n"
                f"Contact: <sip:{INTERFACE_IP}:{RESPONSE_PORT}>\r\n"
                "Event: ua-profile;profile-type=\"device\";vendor=\"Grandstream\";model=\"GRP2601P\";version=\"1.0.5.68\"\r\n"
                "User-Agent: Grandstream UCM630X\r\n"
                "Expires: 0\r\n"
                "Content-Length: 0\r\n"
                "\r\n"
            )

            # Use a socket bound to port 6060 for responses
            reply_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            reply_socket.bind((INTERFACE_IP, RESPONSE_PORT))  # Bind to 6060
            reply_socket.sendto(response.encode(), addr)
            log_verbose(f"Sent 202 Accepted response to {addr} from port {RESPONSE_PORT}")
            reply_socket.close()

            # Send NOTIFY
            cseq = 1
            send_notify(addr, call_id, cseq, RESPONSE_PORT, from_tag, to_tag, site)

class ConfigFileHandler(SimpleHTTPRequestHandler):
    """Serve configuration files from mapped site folders."""
    def do_GET(self):
        requested_file = self.path.strip("/").rstrip("/")
        log_verbose(f"Requested path: {self.path}")
        log_verbose(f"Normalized path: {requested_file}")

        if requested_file.startswith("kgzcaps/cfg") and requested_file.endswith(".xml"):
            mac_address = requested_file.split("cfg")[-1].replace(".xml", "")
            log_verbose(f"Extracted MAC address: {mac_address}")

            # Search for the file in all site folders under kgzcaps
            for site, folder in site_folder_map.items():
                file_path = os.path.join(folder, f"cfg{mac_address}.xml")
                log_verbose(f"Checking for file in: {file_path}")

                if os.path.exists(file_path):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/xml")
                    self.send_header("Content-Length", str(os.path.getsize(file_path)))
                    self.end_headers()
                    with open(file_path, "rb") as file:
                        self.wfile.write(file.read())
                    log_verbose(f"Served: {file_path}")
                    return

            log_verbose("File not found, returning 404.")
            self.send_error(404, "File Not Found")
            return

        log_verbose("Invalid request path, returning 404.")
        self.send_error(404, "Invalid Request Path")
        
    def log_message(self, format, *args):
        """Redirect HTTP server log messages to verbose logging."""
        log_verbose(f"HTTP Request: {self.address_string()} - {format % args}")

def https_server(site):
    # Create an HTTP server
    httpd = HTTPServer(("0.0.0.0", HTTPS_PORT), ConfigFileHandler)

    # Add SSL/TLS to the server
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(certfile=TLS_CERT, keyfile=TLS_KEY)
    httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True)

    time.sleep(1.4)
    log_verbose(f"HTTPs Server listening on port {HTTPS_PORT}")
    httpd.serve_forever()

def is_grandstream_device(mac_address):
    """Check if the MAC address belongs to a Grandstream device."""
    mac_prefix = mac_address.upper()[:8]
    return mac_prefix in ALLOWED_OUIS

def get_local_ip(network_segment, network):
    """
    Automatically fetch the server's IP that matches the given network segment.
    """
    hostname = socket.gethostname()
    local_ips = socket.gethostbyname_ex(hostname)[2]
    for ip in local_ips:
        if ipaddress.IPv4Address(ip) in network:
            return ip
    raise ValueError("No local IP matches the specified network segment.")

def generate_ip_pool(network_segment, dhcpd_start_ip, dhcpd_end_ip, network):
    """
    Generate a list of individual IPs within the specified range in the given network segment.
    """
    start = ipaddress.IPv4Address(dhcpd_start_ip)
    end = ipaddress.IPv4Address(dhcpd_end_ip)

    if start not in network or end not in network:
        raise ValueError("Start or end IP is outside the specified network segment.")

    # Generate all individual IPs within the range
    return [str(ipaddress.IPv4Address(ip)) for ip in range(int(start), int(end) + 1)]

def build_dhcp_packet(transaction_id, client_ip, server_ip, mac_address, lease_time, dhcpd_subnet_mask, dhcpd_broadcast_address, network, dhcpd_gateway_ip, dhcpd_dns_ip, message_type):

    # Ensure transaction_id is an integer
    if not isinstance(transaction_id, int):
        raise ValueError(f"Transaction ID must be an integer, got {type(transaction_id)}")

    # Convert IPs to binary format
    client_ip_bin = socket.inet_aton(client_ip)
    server_ip_bin = socket.inet_aton(server_ip)
    subnet_mask_bin = socket.inet_aton(dhcpd_subnet_mask)  # Default subnet mask
    broadcast_address_bin = socket.inet_aton(dhcpd_broadcast_address)  # Replace with appropriate broadcast
    router_bin = socket.inet_aton(str(dhcpd_gateway_ip))  # Default router is the server IP
    dns_server_bin = socket.inet_aton(dhcpd_dns_ip)  # Default DNS server is the server IP
    lease_time_bin = struct.pack("!I", int(lease_time))  # Lease time
    renewal_time_bin = struct.pack("!I", int(lease_time // 2))  # Renewal time (T1)
    rebinding_time_bin = struct.pack("!I", int(lease_time * 0.875))  # Rebinding time (T2)

    # DHCP header
    dhcp_header = struct.pack(
        "!BBBBIHHIIII16s64s128s4s",
        2,  # Message type: Boot Reply
        1,  # Hardware type: Ethernet
        6,  # Hardware address length
        0,  # Hops
        transaction_id,  # Transaction ID
        0,  # Seconds elapsed
        0,  # Bootp flags
        0,  # Client IP address (usually 0 for initial response)
        struct.unpack("!I", client_ip_bin)[0],  # Your (client) IP address
        struct.unpack("!I", server_ip_bin)[0],  # Next server IP address
        0,  # Relay agent IP address
        bytes.fromhex(mac_address.replace(':', '')),  # Client MAC address
        b'\x00' * 64,  # Server host name
        b'\x00' * 128,  # Boot file name
        b'\x63\x82\x53\x63'  # Magic cookie: DHCP
    )

    offer_bit = (
        b'\x35\x01\x02'  # DHCP Message Type: Offer
    )
    
    ack_bit = (
        b'\x35\x01\x05'  # DHCP Message Type: ACK
    )
    
    # DHCP options
    other_dhcp_options = (
        b'\x36\x04' + server_ip_bin  # DHCP Server Identifier
        + b'\x33\x04' + lease_time_bin  # Lease Time
        + b'\x3a\x04' + renewal_time_bin  # Renewal Time Value (T1)
        + b'\x3b\x04' + rebinding_time_bin  # Rebinding Time Value (T2)
        + b'\x01\x04' + subnet_mask_bin  # Subnet Mask
        + b'\x1c\x04' + broadcast_address_bin # Broadcast Address
        + b'\x03\x04' + router_bin  # Router
        + b'\x06\x04' + dns_server_bin  # DNS Server
        + b'\x0f' + bytes([len("lan")]) + b'lan'  # Domain Name (adjust as needed)
        + b'\xff'  # End option
    )

    if message_type == 1:
        padding = b'\x00' * (300 - len(dhcp_header + offer_bit + other_dhcp_options))
        return dhcp_header + offer_bit + other_dhcp_options + padding
    if message_type == 3:
        padding = b'\x00' * (300 - len(dhcp_header + ack_bit + other_dhcp_options))
        return dhcp_header + ack_bit + other_dhcp_options + padding

def handle_dhcp_request(dhcpd_data, dhcpd_addr, ip_pool, server_ip, lease_time, server_socket, dhcpd_subnet_mask, dhcpd_broadcast_address, network, dhcpd_gateway_ip, dhcpd_dns_ip):
    global leases  # Ensure we can access and modify the global 'leases' dictionary

    try:
        # Parse incoming data
        transaction_id = struct.unpack("!I", dhcpd_data[4:8])[0]
        mac_address = ':'.join(f"{b:02x}" for b in dhcpd_data[28:34])
        log_verbose(f"Transaction ID: {transaction_id}, Client MAC: {mac_address}")

        # Filter non-Grandstream devices
        if not is_grandstream_device(mac_address):
            log_verbose(f"Ignoring DHCP request from non-Grandstream device: {mac_address}")
            return

        # Extract DHCP Message Type (Option 53)
        options = dhcpd_data[240:]  # Skip the fixed header to parse options
        message_type = None
        i = 0
        while i < len(options):
            option_type = options[i]
            if option_type == 53:  # DHCP Message Type
                message_type = options[i + 2]  # The value is 2 bytes ahead
                break
            i += 2 + options[i + 1]  # Move to the next option

        if message_type == 1:  # DHCP DISCOVER
            # Allocate an IP address
            client_ip = ip_pool.pop(0) if mac_address not in leases else leases[mac_address]
            leases[mac_address] = client_ip
            log_verbose(f"Assigning IP {client_ip} to {mac_address}")

            # Build and send DHCP OFFER packet
            offer_packet = build_dhcp_packet(transaction_id, client_ip, server_ip, mac_address, lease_time, dhcpd_subnet_mask, dhcpd_broadcast_address, network, dhcpd_gateway_ip, dhcpd_dns_ip, message_type)
            server_socket.sendto(offer_packet, (dhcpd_broadcast_address, 68))

            log_verbose(f"DHCP OFFER sent to {mac_address} for IP {client_ip}")

        elif message_type == 3:  # DHCP REQUEST
            if mac_address in leases:
                client_ip = leases[mac_address]
                log_verbose(f"Client {mac_address} requested IP {client_ip}")

                # Build and send DHCP ACK packet
                ack_packet = build_dhcp_packet(transaction_id, client_ip, server_ip, mac_address, lease_time, dhcpd_subnet_mask, dhcpd_broadcast_address, network, dhcpd_gateway_ip, dhcpd_dns_ip, message_type)
                server_socket.sendto(ack_packet, (dhcpd_broadcast_address, 68))
                log_verbose(f"DHCP ACK sent to {mac_address} for IP {client_ip}")
            else:
                log_verbose(f"Client {mac_address} requested an unknown IP. Ignoring.")

    except Exception as e:
        print(f"Error processing request: {e}")

def run_dhcp_server(ip_pool, server_ip, lease_time, dhcpd_subnet_mask, dhcpd_broadcast_address, network, dhcpd_gateway_ip, dhcpd_dns_ip):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    server_socket.bind(("0.0.0.0", 67))
    server_socket.settimeout(1.0)  # Set a timeout of 1 second for the socket

    time.sleep(1.2)
    log_verbose("DHCP server is running...")

    try:
        while True:
            try:
                dhcpd_data, dhcpd_addr = server_socket.recvfrom(1024)
                log_verbose(f"Received data from {dhcpd_addr}")
                handle_dhcp_request(dhcpd_data, dhcpd_addr, ip_pool, server_ip, lease_time, server_socket, dhcpd_subnet_mask, dhcpd_broadcast_address, network, dhcpd_gateway_ip, dhcpd_dns_ip)
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        print("\nShutting down DHCP server.")
    finally:
        server_socket.close()

def main():
    global IPPBX_IP, INTERFACE_IP, extension_counter, SIP_AUTH_PASS ,start_ip, subnet_mask, gateway_ip, dns_ip, ip_mode, dhcpd_start_ip, dhcpd_end_ip, leases, TLS_CERT, TLS_KEY
    loading()
    total_steps = 100
    print()
    interfaces = get_ip_addresses()
    interface, INTERFACE_IP = choose_interface(interfaces)
    print(f"You have chosen Interface: {interface}, IP Address: {INTERFACE_IP}")

    site = input("Enter Site Name > ")
    path = get_config_file(site, TLS_CERT, TLS_KEY)
    assingment_file_path, site_folder_path = path

    if IPPBX_IP == "":
        while True:
            IPPBX_IP = input("Enter the IPPBX IP address > ")
            if is_valid_ip(IPPBX_IP):
                if is_valid_subnet_mask(IPPBX_IP):
                    print("Entered value is Subnet Mask not IP Addresss")
                    continue
                else:
                    break
            else:
                print("Invalid IP address. Please enter a valid IPv4 address.")
                
    if extension_counter == "":
        while True:
            extension_counter = input("Enter Starting Sip User ID number > ")
            if is_numeric(extension_counter):
                extension_counter = int(extension_counter)
                break

    while not SIP_AUTH_PASS :
        SIP_AUTH_PASS  = input("Enter Sip Autentication Password > ")

    if ip_mode == "":
        while True: 
            ip_mode = input("Enter IP Phone network mode (1. DHCP 2. Static) > ")
            if ip_mode in ("1" ,"2"):
                break
    ip_mode = int(ip_mode)
    if ip_mode == 2:
        if start_ip == "":
            while True:
                start_ip = input("Enter the IP Phone starting IP address > ")
                if is_valid_ip(start_ip):
                    if is_valid_subnet_mask(start_ip):
                        print("Entered value is Subnet Mask not IP Addresss")
                        continue
                    else:
                        break
                else:
                    print("Invalid IP address. Please enter a valid IPv4 address.")
        if subnet_mask == "":
            while True:
                print("Enter the Subnet Mask default (255.255.255.0) > ", end="")
                subnet_mask = input() or "255.255.255.0"
                try:
                    if int(subnet_mask) <= 32:
                        print("Invalid IP address. Please enter a valid Subnet Mask.")
                        continue
                except:
                    if is_valid_subnet_mask(subnet_mask):
                        break
                    else:
                        print("Invalid IP address. Please enter a valid Subnet Mask.")
        default_gateway = start_ip.rsplit(".", 1)[0] + ".1"
        if gateway_ip == "":
            while True:
                print(f"Enter the Gateway IP address default ({default_gateway}) > ", end="")
                gateway_ip = input() or default_gateway
                if is_valid_ip(gateway_ip):
                    if is_valid_subnet_mask(gateway_ip):
                        print("Entered value is Subnet Mask not IP Addresss")
                        continue
                    else:
                        break
                else:
                    print("Invalid IP address. Please enter a valid IPv4 address.")            
        if dns_ip == "":
            while True:                        
                dns_ip = input("Enter the DNS IP address default (8.8.8.8) > ") or "8.8.8.8"
                if is_valid_ip(dns_ip):
                    if is_valid_subnet_mask(dns_ip):
                        print("Entered value is Subnet Mask not IP Addresss")
                        continue
                    else:
                        break
                else:
                    print("Invalid IP address. Please enter a valid IPv4 address.")
    
    if args.PCODE:
        for key, value in additional_cfg.items():     
            print(f"""P{key} - {value}""")
        add_p_code = input("Do you want to add or modify P codes? (yes/no): ").strip().lower()
        if add_p_code not in ['yes', 'no']:
            print("[ERROR] Invalid input. continuing...")
        while add_p_code == "yes":
            p_code = input("P Code: ")
            p_value = input("P Code Vlaue: ")
            additional_cfg[p_code] = p_value
            add_p_code = input("Do you want to add or modify another P code? (yes/no): ").strip().lower()
            for key, value in additional_cfg.items():     
                print(f"""P{key} - {value}""")

    if args.dhcpd:
        print("DHCP Server Configuration")
        if dhcpd_start_ip == "":
            while True:
                dhcpd_start_ip = input("Enter DHCP Starting IP address > ")
                if is_valid_ip(dhcpd_start_ip):
                    if is_valid_subnet_mask(dhcpd_start_ip):
                        print("Entered value is Subnet Mask not IP Addresss")
                        continue
                    else:
                        break
                else:
                    print("Invalid IP address. Please enter a valid IPv4 address.")
        if dhcpd_end_ip == "":
            while True:
                dhcpd_end_ip = input("Enter DHCP Ending IP address > ")
                if is_valid_ip(dhcpd_end_ip):
                    if is_valid_subnet_mask(dhcpd_end_ip):
                        print("Entered value is Subnet Mask not IP Addresss")
                        continue
                    else:
                        break
                else:
                    print("Invalid IP address. Please enter a valid IPv4 address.")

        dhcpd_gateway_ip = gateway_ip
        dhcpd_subnet_mask = subnet_mask
        dhcpd_dns_ip = dns_ip
        
        lease_time = 7200  # Ensure this is an integer

        if not dhcpd_gateway_ip:
            print("Gateway ip address is not entered.")
            sys.exit(1)
        network = ipaddress.IPv4Network(f"{dhcpd_gateway_ip}/{dhcpd_subnet_mask}", strict=False)
        network_segment = str(network)
        dhcpd_gateway_ip = ipaddress.IPv4Address(dhcpd_gateway_ip)
        dhcpd_broadcast_address = str(network.broadcast_address)
        dhcpd_subnet_mask = str(network.netmask)

        try:
            server_ip = get_local_ip(network_segment, network)
            print(f"Automatically detected server IP: {server_ip}")
        except ValueError as e:
            print(e)
            exit(1)

        ip_pool = generate_ip_pool(network_segment, dhcpd_start_ip, dhcpd_end_ip, network)
        log_verbose(f"IP pool generated: {ip_pool}")
        print("Number of IP Address in Pool", len(ip_pool))

    generate_from_config_file(site, SIP_AUTH_PASS , str(start_ip), subnet_mask, gateway_ip, dns_ip, additional_cfg)

    # Run Servers
    Thread(target=sip_server, args=(site, SIP_AUTH_PASS, assingment_file_path ,start_ip, subnet_mask, gateway_ip, dns_ip, additional_cfg,), daemon=True).start()
    Thread(target=https_server, args=(site,), daemon=True).start()
    if args.dhcpd:
        Thread(target=run_dhcp_server, args=(ip_pool, server_ip, lease_time, dhcpd_subnet_mask, dhcpd_broadcast_address, network, dhcpd_gateway_ip, dhcpd_dns_ip), daemon=True).start()

    if args.dhcpd:
        print("Starting SIP, HTTPs and DHCP server")  # Print a newline    
    else:
        print("Starting SIP and HTTPs server")  # Print a newline    
    progress_bar(0, total_steps)
    
    # Simulate a task that takes time (e.g., reading files, processing data, etc.)
    for i in range(total_steps):
        time.sleep(loading_time)  # Simulating work (replace with real task)
        progress_bar(i + 1, total_steps)
    print()  # Print a newline after completion    
    print()  # Print a newline after completion    

    if args.verbose:
        time.sleep(1)
    print("kgzcaps will keep running until stopped. Press Ctrl+C to stop.")
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\nkgzcaps Stop Running.")

try:
    if __name__ == "__main__":
        main()
except:
   print("\nkgzcaps Stop Running.")

finally:
    print("\n[kgzcaps_v{}]:".format(version))
