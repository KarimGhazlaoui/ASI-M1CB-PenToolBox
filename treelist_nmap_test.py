import sys
import subprocess
from PyQt5.QtWidgets import QApplication, QTreeWidget, QTreeWidgetItem


def nmap_scan(network):
    # Appel de Nmap via subprocess
    nmap_command = ['nmap', '-A', network]  # Option -A pour obtenir des informations détaillées
    nmap_process = subprocess.Popen(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = nmap_process.communicate()

    results = []

    # Analyse des résultats de la sortie de Nmap
    for line in stdout.splitlines():
        line = line.decode('utf-8')  # Convertit bytes en str
        if "Nmap scan report for" in line:
            host_item = QTreeWidgetItem([line.split()[-1]])  # Ajoute l'adresse IP du host
            results.append(host_item)
        elif "/tcp" in line:
            port, state, service = line.split()[:3]
            port_item = QTreeWidgetItem([f"Port {port}"])
            host_item.addChild(port_item)
            port_item.addChild(QTreeWidgetItem([f"Service : {service}"]))
        elif "OS details" in line:
            os_details_index = line.find(":")
            if os_details_index != -1:  # Vérifier si le séparateur ':' est présent dans la ligne
                os_details = line[os_details_index + 1:].strip()
                host_item.addChild(QTreeWidgetItem([f"OS details : {os_details}"]))
        elif "Host is up" in line:
            host_item.addChild(QTreeWidgetItem(["Host is up"]))
        elif "Latency" in line:
            latency = line.split()[1]
            host_item.addChild(QTreeWidgetItem([f"Latency : {latency}"]))

    return results


class MainWindow(QTreeWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Nmap Scanner")
        self.setHeaderLabels(["Résultats"])
        self.resize(600, 400)

        self.populate_tree()

    def populate_tree(self):
        network = "192.168.1.0/24"  # Réseau à scanner
        scan_results = nmap_scan(network)

        for item in scan_results:
            self.addTopLevelItem(item)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
