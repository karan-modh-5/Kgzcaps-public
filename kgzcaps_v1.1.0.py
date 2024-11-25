import csv
import argparse
import sys
import re
import ipaddress
import os
import shutil
import math
import time
import ipaddress
import socket
import struct
import ssl
from http.server import HTTPServer, SimpleHTTPRequestHandler
from threading import Thread

version = "1.1.0" # Version of the script

# Variables for storing input parameters
IPPBX_IP = ""
loading_time = 0.01 # Time delay for the loading effect
# Replace with the correct Ethernet interface IP
INTERFACE_IP = ""  # Update this to match your Ethernet IP
extension_counter = ""  # Starting extension number
start_ip = ""
subnet_mask = ""
gateway_ip = ""
dns_ip = ""
ip_mode = ""
SIP_AUTH_PASS = ""
provisioned_devices = {}
#CONFIG_FOLDER = "zccgi"
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
parser.add_argument("-V", "--verbose", action="store_true", help="Enable verbose mode")

# Parse the command-line arguments
args = parser.parse_args()

# Handle version argument
if args.v:
    print("\nkgzcaps version: {}".format(version))
    sys.exit(0)

# Model input validation
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

# Verbose flag
VERBOSE_MODE = args.verbose

def log_verbose(message):
    """Print verbose messages if verbose mode is enabled."""
    if VERBOSE_MODE:
        print(f"[VERBOSE] {message}")

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

def get_config_file(site):
    """Get or create the folder path for a site."""
    kgzcaps = "kgzcaps"
    script_directory = os.getcwd()  # Get the current script directory
    folder_path = os.path.join(script_directory, kgzcaps, site)  # Include kgzcaps in the path
    
    # Update the global mapping
    site_folder_map[site] = folder_path

    # Create the directory if it doesn't exist
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
        print(f"Folder '{folder_path}' created successfully.")
    else:
        print(f"Folder '{folder_path}' already exists.")

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


def generate_config_file(mac_address, extension, SIP_AUTH_PASS ):
    """Generate configuration content dynamically."""
    return f"""<?xml version="1.0" encoding="UTF-8" ?>
<gs_provision version="1">
    <mac>{mac_address}</mac>
    <config version="1">
        <P2>{SIP_AUTH_PASS}</P2>
        <P102>2</P102>
        <P30>{IPPBX_IP}</P30>
        <P64>TZT-5:30</P64>
        <P122>0</P122>
        <P414>0</P414>
        <P52>2</P52>
        <P104>2</P104>
        <P2348>1</P2348>
        <P2397>1</P2397>
        <P26073>0</P26073>
        <P78>1</P78>
        <P8350>1</P8350>
        <P8351>2</P8351>
        <P8446>0</P8446>
        <P35>{extension}</P35>
        <P270>{extension}</P270>
        <P36>{extension}</P36>
        <P34>{SIP_AUTH_PASS}</P34>
        <P33>*97</P33>
        <P271>1</P271>
        <P48></P48>
        <P47>{IPPBX_IP}</P47>
        <P1558>26</P1558>
    </config>
</gs_provision>
"""

def generate_config_file_for_static_mode(mac_address, extension, SIP_AUTH_PASS ,ip , subnet_mask, gateway_ip, dns_ip):
    """Generate configuration content dynamically."""
    return f"""<?xml version="1.0" encoding="UTF-8" ?>
<gs_provision version="1">
    <mac>{mac_address}</mac>
    <config version="1">
        <P2>{SIP_AUTH_PASS}</P2>
        <P102>2</P102>
        <P30>{IPPBX_IP}</P30>
        <P64>TZT-5:30</P64>
        <P122>0</P122>
        <P414>0</P414>
        <P52>2</P52>
        <P104>2</P104>
        <P2348>1</P2348>
        <P2397>1</P2397>
        <P26073>0</P26073>
        <P78>1</P78>
        <P8350>1</P8350>
        <P8351>2</P8351>
        <P8446>0</P8446>
        <P35>{extension}</P35>
        <P270>{extension}</P270>
        <P36>{extension}</P36>
        <P34>{SIP_AUTH_PASS}</P34>
        <P33>*97</P33>
        <P271>1</P271>
        <P48></P48>
        <P47>{IPPBX_IP}</P47>
        <P1558>26</P1558>
        <P8>1</P8>
        <P9>{ip.split('.')[0]}</P9>
        <P10>{ip.split('.')[1]}</P10>
        <P11>{ip.split('.')[2]}</P11>
        <P12>{ip.split('.')[3]}</P12>
        <P13>{subnet_mask.split('.')[0]}</P13>
        <P14>{subnet_mask.split('.')[1]}</P14>
        <P15>{subnet_mask.split('.')[2]}</P15>
        <P16>{subnet_mask.split('.')[3]}</P16>
        <P17>{gateway_ip.split('.')[0]}</P17>
        <P18>{gateway_ip.split('.')[1]}</P18>
        <P19>{gateway_ip.split('.')[2]}</P19>
        <P20>{gateway_ip.split('.')[3]}</P20>        
        <P21>{dns_ip.split('.')[0]}</P21>        
        <P22>{dns_ip.split('.')[1]}</P22>        
        <P23>{dns_ip.split('.')[2]}</P23>        
        <P24>{dns_ip.split('.')[3]}</P24>        
    </config>
</gs_provision>
"""

def save_config_file(mac_address, extension_counter, site, SIP_AUTH_PASS ,ip , subnet_mask, gateway_ip, dns_ip):
    """Save configuration file in the specific site folder."""
    folder = site_folder_map.get(site)
    if not folder:
        print(f"Error: Site {site} folder not found.")
        return

    file_name = os.path.join(folder, f"cfg{mac_address}.xml")
    if ip_mode == 1:
        config_content = generate_config_file(mac_address, extension_counter, SIP_AUTH_PASS )
    if ip_mode == 2:
        config_content = generate_config_file_for_static_mode(mac_address, extension_counter, SIP_AUTH_PASS ,ip , subnet_mask, gateway_ip, dns_ip)
    with open(file_name, "w") as config_file:
        config_file.write(config_content)
    log_verbose(f"Configuration file created: {file_name}")

# Function to send NOTIFY packet
def send_notify(addr, call_id, cseq, port, from_tag, to_tag, site):
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
        f"Content-Length: 34\r\n"
        f"\r\n"
        f"https://{INTERFACE_IP}:{HTTPS_PORT}/kgzcaps/\r\n"
    )

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as notify_socket:
        notify_socket.bind((INTERFACE_IP, port))  # Bind to 6060
        notify_socket.sendto(notify_message.encode(), addr)
        log_verbose(f"Sent NOTIFY to {addr} from port {port}")

# Function to handle SIP SUBSCRIBE
def sip_server(site, SIP_AUTH_PASS, assingment_file_path ,start_ip, subnet_mask, gateway_ip, dns_ip):
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
            if mac_address not in provisioned_devices:
                # Assign a new extension and save the configuration file
                provisioned_devices[mac_address] = extension_counter
                save_config_file(mac_address, extension_counter, site, SIP_AUTH_PASS ,str(start_ip) , subnet_mask, gateway_ip, dns_ip)
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
            call_id = next((h.split(": ")[1] for h in headers if h.startswith("Call-ID:")), "259599202@192.168.43.160")
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
                "Event: ua-profile;profile-type=\"device\";vendor=\"Grandstream\";model=\"GRP2601P\";version=\"1.0.5.55\"\r\n"
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

    time.sleep(1)
    log_verbose(f"HTTPs Server listening on port {HTTPS_PORT}")
    httpd.serve_forever()

def main():
    global IPPBX_IP, INTERFACE_IP, extension_counter, SIP_AUTH_PASS ,start_ip, subnet_mask, gateway_ip, dns_ip, ip_mode
    loading()
    total_steps = 100
    print()
    interfaces = get_ip_addresses()
    interface, INTERFACE_IP = choose_interface(interfaces)
    print(f"You have chosen Interface: {interface}, IP Address: {INTERFACE_IP}")

    site = input("Enter Site Name > ")
    path = get_config_file(site)
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
            

  
    # Run Servers
    Thread(target=sip_server, args=(site, SIP_AUTH_PASS, assingment_file_path ,start_ip, subnet_mask, gateway_ip, dns_ip,), daemon=True).start()
    Thread(target=https_server, args=(site,), daemon=True).start()

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
