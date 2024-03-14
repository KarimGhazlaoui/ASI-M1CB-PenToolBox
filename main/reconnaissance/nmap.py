import subprocess
import netifaces
import ipaddress
import threading

nmap_path = r"tools\nmap\nmap.exe"

scan_en_cours = threading.Event()
resultat_scan = None

# Fonction pour récupérer le sous-réseau actuellement utilisé par l'host
def get_network_interface_info():
    # Get the default gateway IP address
    gateway_ip = netifaces.gateways()['default'][netifaces.AF_INET][0]

    # Get the IP address and subnet mask of the network interface connected to the local network
    interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
    interface_info = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
    ip_address = interface_info['addr']
    subnet_mask = interface_info['netmask']

    # Convert subnet mask to CIDR notation
    cidr = str(ipaddress.IPv4Network('0.0.0.0/' + subnet_mask).prefixlen)

    return ip_address, cidr

# Fonction lançant le scan NMAP
def scannmap(command=None):

    global resultat_scan
    command = f"{nmap_path} {command}"

    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
        resultat_scan = output
    except subprocess.CalledProcessError as e:
        resultat_scan = e.output
    finally:
        scan_en_cours.set()
    
def scan(command):
    global resultat_scan
    
    scan_en_cours.clear()

    thread = threading.Thread(target=scannmap, args=(command,))
    thread.start()

    scan_en_cours.wait()

    return resultat_scan

# Fonction qui traite le résultat en tant que dictionnaire
def process_result(result):
    # Filter the result
    filtered_result = [line.strip() for line in result.split('\n') if line.startswith(('Nmap scan', 'Host', 'MAC Address'))]

    # Create a dictionary to store the information
    hosts = {}
    current_host = None

    # Iterate through the filtered lines
    for line in filtered_result:
        if line.startswith('Nmap scan report'):
            # If it's a new host, update the current_host variable
            current_host = line.split('for ')[1]
            hosts[current_host] = {}
        elif ':' in line:
            # If the line contains a ':', split it and add it to the dictionary
            key, value = line.split(': ', 1)
            hosts[current_host][key] = value
        else:
            # If the line doesn't contain a ':', add it as a new key with an empty value
            key = line
            hosts[current_host][key] = ""

    return hosts
