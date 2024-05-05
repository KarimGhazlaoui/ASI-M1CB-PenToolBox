import csv
from app.scripts.qemu_script import QemuSSHManager
from datetime import datetime
import xml.etree.ElementTree as ET
import time

class gvm():
    def __init__(self, main_instance) -> None:
        self.main_instance = main_instance
        self.taskid = ""
        self.ssh_manager = QemuSSHManager()

    def scan_vulnerabilite(self, cible_vulnerabilite=None):

        gvm_reponse = ""

        cible_vulnerabilite = ','.join(cible_vulnerabilite)
        current_datetime = datetime.now()
        datetime_cible = current_datetime.strftime("%d/%m/%Y %H:%M:%S")
        command_to_execute = f"""gvm-cli socket --xml "<create_target><name>{datetime_cible}</name><hosts>{cible_vulnerabilite}</hosts><port_list id=\\"4a4717fe-57d2-11e1-9a26-406186ea4fc5\\"/></create_target>" --pretty"""
        print(command_to_execute)
        completion_indicator = "command completed"

        print("Création de la cible GVM..")
        self.main_instance.liveupdate("Création de la cible GVM...")

        for line in self.ssh_manager.execute_command_live(command_to_execute):
            self.main_instance.liveupdate(line)
            print(line)
            gvm_reponse += line
            if line.strip('\n') == completion_indicator:
                break

        start_index = gvm_reponse.find('<create_target_response')
        end_index = gvm_reponse.rfind('/>') + 2  # Adding 2 to include the end tag
        xml_content = gvm_reponse[start_index:end_index]

        gvm_reponse = ET.fromstring(xml_content)

        status = gvm_reponse.attrib.get('status')
        id_cible = gvm_reponse.attrib.get('id')

        gvm_reponse = ""

        command_to_execute = f"""gvm-cli socket --xml "<create_task><name>{datetime_cible}</name> <target id=\\"{id_cible}\\"></target><config id=\\"daba56c8-73ec-11df-a475-002264764cea\\"></config></create_task>" --pretty"""
        print(command_to_execute)
        print("Création de la tâche GVM..")
        self.main_instance.liveupdate("Création de la tâche GVM...")

        for line in self.ssh_manager.execute_command_live(command_to_execute):
            self.main_instance.liveupdate(line)
            print(line)
            gvm_reponse += line
            if line.strip('\n') == completion_indicator:
                break

        start_index = gvm_reponse.find('<create_task_response')
        end_index = gvm_reponse.rfind('/>') + 2  # Adding 2 to include the end tag
        xml_content = gvm_reponse[start_index:end_index]

        gvm_reponse = ET.fromstring(xml_content)

        id_task = gvm_reponse.attrib.get('id')
        self.taskid = id_task

        gvm_reponse = ""

        command_to_execute = f"""gvm-cli socket --xml '<start_task task_id="{id_task}"/>' --pretty"""
        print(command_to_execute)
        print("Démarrage de la tâche GVM...")
        self.main_instance.liveupdate("Démarrage de la tâche GVM...")
        for line in self.ssh_manager.execute_command_live(command_to_execute):
            self.main_instance.liveupdate(line)
            print(line)
            gvm_reponse += line
            if line.strip('\n') == completion_indicator:
                break

    def status_live_update(self):
        completion_indicator = "command completed"
        while True:
            command_to_execute = f"""gvm-cli socket --xml '<get_tasks task_id="{self.taskid}"/>' --pretty"""
            gvm_response = ""
            
            for line in self.ssh_manager.execute_command_live(command_to_execute):
                self.main_instance.liveupdate(line)
                print(line)
                gvm_response += line
                if line.strip('\n') == completion_indicator:
                    break
            
            # Check if the status is "Done" or not
            root = ET.fromstring(gvm_response)
            for task in root.findall('.//task'):
                status_element = task.find('status')
                if status_element is not None:
                    status = status_element.text.strip()
                    print("Status:", status)
                    if status == "Done":
                        return  # Exit the function if status is "Done"
            
            # Pause execution for 15 seconds before the next iteration
            time.sleep(15)

    def traitement_csv(self, donnee_csv):
        scan_resultat = []
        lines = donnee_csv.strip().split('\n')
        header = lines[0].strip().split(',')
        reader = csv.DictReader(lines[1:], fieldnames=header)
        for row in reader:
            scan_resultat.append({
                'IP': row.get('IP', ''),
                'Port': row.get('Port', ''),
                'Protocole': row.get('Port Protocol', ''),
                'Sévérité': row.get('Severity', ''),
                'NVT': row.get('NVT Name', ''),
                'CVE': row.get('CVEs', '')
            })
        return scan_resultat
