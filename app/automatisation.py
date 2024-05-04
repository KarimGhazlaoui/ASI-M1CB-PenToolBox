from app.scripts.qemu_script import QemuSSHManager
from app.interface.cible_interface import CibleInterface
import netifaces
import ipaddress
import re
from datetime import datetime
import xml.etree.ElementTree as ET

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

    def scan_vulnerabilite(self, cible_vulnerabilite=None):
        ssh_manager = QemuSSHManager()

        gvm_reponse = ""

        cible_vulnerabilite = ','.join(cible_vulnerabilite)
        current_datetime = datetime.now()
        datetime_cible = current_datetime.strftime("%d/%m/%Y %H:%M:%S")
        command_to_execute = f"""gvm-cli socket --xml "<create_target><name>{datetime_cible}</name><hosts>{cible_vulnerabilite}</hosts><port_list id=\\"4a4717fe-57d2-11e1-9a26-406186ea4fc5\\"/></create_target>" --pretty"""
        print(command_to_execute)
        completion_indicator = "command completed"

        print("Création de la cible GVM..")
        for line in ssh_manager.execute_command_live(command_to_execute):
            print(line)
            gvm_reponse += line
            self.nmap_sortie += line + '\n'
            if line.strip('\n') == completion_indicator:
                break

        start_index = gvm_reponse.find('<create_target_response')
        end_index = gvm_reponse.rfind('/>') + 2  # Adding 2 to include the end tag
        xml_content = gvm_reponse[start_index:end_index]

        gvm_reponse = ET.fromstring(xml_content)

        status = gvm_reponse.attrib.get('status')
        id_cible = gvm_reponse.attrib.get('id')

        gvm_reponse = ""

        command_to_execute = f"""gvm-cli socket --xml "<create_task><name>{datetime_cible}</name> <target id=\\"{id_cible}\\"></target><config id=\\"4be0e123-e2bc-424d-a84e-bc842414aa61\\"></config></create_task>" --pretty"""
        print(command_to_execute)
        print("Création de la tâche GVM..")
        for line in ssh_manager.execute_command_live(command_to_execute):
            print(line)
            gvm_reponse += line
            self.nmap_sortie += line + '\n'
            if line.strip('\n') == completion_indicator:
                break

        start_index = gvm_reponse.find('<create_task_response')
        end_index = gvm_reponse.rfind('/>') + 2  # Adding 2 to include the end tag
        xml_content = gvm_reponse[start_index:end_index]

        gvm_reponse = ET.fromstring(xml_content)

        id_task = gvm_reponse.attrib.get('id')

        gvm_reponse = ""

        command_to_execute = f"""gvm-cli socket --xml '<start_task task_id="{id_task}"/>' --pretty"""
        print(command_to_execute)
        print("Démarrage de la tâche GVM..")
        for line in ssh_manager.execute_command_live(command_to_execute):
            print(line)
            gvm_reponse += line
            self.nmap_sortie += line + '\n'
            if line.strip('\n') == completion_indicator:
                break


        # Close the SSH connection
        ssh_manager.close_connection()

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