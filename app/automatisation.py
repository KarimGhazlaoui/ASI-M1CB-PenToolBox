from app.scripts.qemu_script import QemuSSHManager
from app.interface.cible_interface import CibleInterface
import netifaces
import ipaddress
import re

class scan_vers_cible:
    def __init__(self) -> None:
        pass

    def lancement_scan(self, sousreseau=None, optionscan=1):
        print(sousreseau)

        self.cibleliste = []
        self.nmap_sortie = ""

        if sousreseau == "":
            ip_address, cidr = self.get_network_interface_info()
            print("IP : " + ip_address + " CIDR : " + cidr)
            ssh_manager = QemuSSHManager()
            command_to_execute = "sudo nmap -PE -sn " + ip_address + "/" + cidr
            completion_indicator = "command completed"

            print("Executing Nmap scan...")
            for line in ssh_manager.execute_command_live(command_to_execute):
                print(line)
                self.nmap_sortie += line + '\n'
                if line.strip('\n') == completion_indicator:
                    break

            # Close the SSH connection
            ssh_manager.close_connection()

        else:
            ssh_manager = QemuSSHManager()
            command_to_execute = "nmap -sn " + sousreseau
            completion_indicator = "command completed"

            print("Executing Nmap scan...")
            for line in ssh_manager.execute_command_live(command_to_execute):
                print(line)
                self.nmap_sortie += line + '\n'
                if line.strip('\n') == completion_indicator:
                    break

            # Close the SSH connection
            ssh_manager.close_connection()

        pattern = r"Nmap scan report for (\S+)\nHost is up \((\d+\.\d+s) latency\)\."
        matches = re.findall(pattern, self.nmap_sortie)

        for match in matches:
            ip = match[0]
            status = f"Host is up ({match[1]} latency)."
            self.cibleliste.append([ip, status])

        return self.cibleliste


    def get_network_interface_info(self):
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