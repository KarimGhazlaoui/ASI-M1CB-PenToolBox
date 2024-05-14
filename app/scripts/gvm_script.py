import csv
from app.scripts.qemu_script import QemuSSHManager
from datetime import datetime
import xml.etree.ElementTree as ET
import base64

class gvm():

    taskid = 0

    def __init__(self, main_instance) -> None:
        self.main_instance = main_instance
        self.taskid = ""
        self.ssh_manager = QemuSSHManager()

    def _execute_command_live(self, command):
        completion_indicator = "command completed"
        response = ""
        for line in self.ssh_manager.execute_command_live(command):
            self.main_instance.liveupdate(line)
            print(line)
            response += line
            if line.strip('\n') == completion_indicator:
                break
        return response

    def scan_vulnerabilite(self, cible_vulnerabilite=None):
        if cible_vulnerabilite is not None:
            cible_vulnerabilite = ','.join(cible_vulnerabilite)
            datetime_cible = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            
            command_target = f"""gvm-cli socket --xml "<create_target><name>{datetime_cible}</name><hosts>{cible_vulnerabilite}</hosts><port_list id=\\"4a4717fe-57d2-11e1-9a26-406186ea4fc5\\"/></create_target>" --pretty"""
            print(command_target)
            print("Création de la cible GVM..")
            self.main_instance.liveupdate("Création de la cible GVM...")
            self.main_instance.gvm_creation(commandssh=command_target, callback=self.create_task)        
        else:
            print("Aucune cible à scanner")

    def create_task(self, response_target):
        datetime_cible = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        print("fonction scan_vulnerabilite : contenu de la response_target :", response_target)
        xml_content = response_target[response_target.find('<create_target_response'):response_target.rfind('/>') + 2]
        target_response = ET.fromstring(xml_content)
        
        id_target = target_response.attrib.get('id')

        command_task = f"""gvm-cli socket --xml "<create_task><name>{datetime_cible}</name><target id=\\"{id_target}\\"></target><config id=\\"daba56c8-73ec-11df-a475-002264764cea\\"></config></create_task>" --pretty"""
        print(command_task)
        print("Création de la tâche GVM..")
        self.main_instance.liveupdate("Création de la tâche GVM...")
        self.main_instance.gvm_creation(commandssh=command_task, callback=self.start_task) 

    def start_task(self, response_task):
        
        xml_content = response_task[response_task.find('<create_task_response'):response_task.rfind('/>') + 2]
        task_response = ET.fromstring(xml_content)
        
        id_task = task_response.attrib.get('id')
        self.taskid = id_task
        gvm.taskid = id_task

        command_start = f"""gvm-cli socket --xml '<start_task task_id="{id_task}"/>' --pretty"""
        print(command_start)
        print("Démarrage de la tâche GVM...")
        self.main_instance.liveupdate("Démarrage de la tâche GVM...")
        self.main_instance.gvm_creation(commandssh=command_start, callback=self.rapport_id)

    def rapport_id(self, response_report):
        start_index = response_report.find('<start_task_response')
        end_index = response_report.find('</start_task_response>') + len('</start_task_response>')
        xml_content = response_report[start_index:end_index]
        task_response = ET.fromstring(xml_content)
        
        report_id_element = task_response.find('report_id')
        if report_id_element is not None:
            id_rapport = report_id_element.text
            self.rapportid = id_rapport
        else:
            print("report_id not found in the XML response.")
        
        self.main_instance.vulnerabilite_status(self.rapportid, gvm.taskid)

    def status_live_update(self, response):        
            root = ET.fromstring(response)
            for task in root.findall('.//task'):
                status_element = task.find('status')
                progress_element = task.find('progress')
                if status_element is not None and progress_element is not None:
                    status = status_element.text.strip()
                    progress = int(progress_element.text.strip())
                    if status in ["Requested", "Queued", "Running", "Done"]:
                        return status, progress
            return None, -1  # If no valid status is found or progress is not available


    def traitement_csv(self, donnee_csv):
        scan_resultat = []
        print(donnee_csv)
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

    def rapport_nettoyage(self, xml_string):
        # Remove everything before word1
        index1 = xml_string.find('</report_format>')
        if index1 != -1:
            xml_string = xml_string[index1 + len('</report_format>'):]

        # Remove everything after word2
        index2 = xml_string.find('</report>')
        if index2 != -1:
            xml_string = xml_string[:index2]

        print(xml_string)

        # Decode the base64 string
        decoded_bytes = base64.b64decode(xml_string)
        # Convert bytes to string
        decoded_text = decoded_bytes.decode('utf-8')  # Assuming utf-8 encoding
        return decoded_text