# coding:utf-8
import sys
import paramiko

from PyQt5.QtCore import QObject, Qt, QThread, pyqtSignal
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication, QWidget, QMessageBox

from qfluentwidgets import SplitFluentWindow, FluentIcon, Flyout, InfoBarIcon, FlyoutAnimationType, MessageBox, NavigationItemPosition

from app.interface.scan_interface import ScanInterface
from app.interface.engagement_interface import EngagementInterface
from app.interface.cible_interface import CibleInterface
from app.interface.vulnerabilite_interface import VulnerabiliteInterface
from app.interface.evaluation_interface import EvaluationInterface
from app.interface.qemu_interface import QemuInterface

from app.scripts.qemu_script import QemuManager
from app.engagement import CustomMessageBox
from app.scripts.profile_script import Profile
from app.scripts.gvm_script import gvm
from app.scripts.rapport_script import RapportGenerateur
from app.automatisation import scan_vers_cible
from app.scripts.qemu_script import QemuManager

import app.resource.resource_rc

class Worker(QThread):
    finished = pyqtSignal()
    result = pyqtSignal(object)

    def __init__(self, function, *args, **kwargs):
        super().__init__()
        self.function = function
        self.args = args
        self.kwargs = kwargs
        self.stopped = False

    def stop(self):
        self.stopped = True

    def run(self):
        if not self.stopped:
            result = self.function(*self.args, **self.kwargs)
            self.result.emit(result)
        self.finished.emit()

class SSHWorker(QThread):
    update_signal = pyqtSignal(str)  # Signal to send updates to the GUI
    finished_signal = pyqtSignal()

    def __init__(self, host='127.0.0.1', port=60022, username='kali', password='root', command=None):
        super().__init__()
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.command = command + ' && echo "command completed"'
        self.output = ""  # Attribute to store command output

    def run(self):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.host, self.port, username=self.username, password=self.password)
            stdin, stdout, stderr = client.exec_command(self.command)
            for line in stdout:
                output_line = line.strip()
                self.update_signal.emit(output_line)
                self.output += output_line + "\n"  # Append output to the attribute
            for line in stderr:
                output_line = line.strip()
                self.update_signal.emit(output_line)
                self.output += output_line + "\n"  # Append output to the attribute
            while not stdout.channel.exit_status_ready():
                pass
            self.finished_signal.emit()
            client.close()
        except Exception as e:
            error_message = f"Error: {str(e)}"
            self.update_signal.emit(error_message)
            self.output += error_message + "\n"  # Append error message to the attribute


class main(SplitFluentWindow):

    automatisation = scan_vers_cible()
    

    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.gvm_management = gvm(self)

        self.worker = None
        
        #CustomMessageBox(self)

        # Localisation des profiles d'entreprises
        self.profile_manager = Profile('app/profiles')
        
        self.qemu_manager = QemuManager()
        self.qemu_manager.start_qemu()

        self.resize(1280, 800)
        self.setWindowTitle("KGB - PenToolBox")
        self.setWindowIcon(QIcon(':/images/logo.png'))

        self.scanInterface = ScanInterface(self)
        #self.engagementInterface = EngagementInterface(self)
        self.cibleInterface = CibleInterface(self)
        self.vulnerabiliteInterface = VulnerabiliteInterface(self)
        self.evaluationInterface = EvaluationInterface(self)
        self.qemuInterface = QemuInterface(self)

        pos = NavigationItemPosition.SCROLL

        #self.addSubInterface(self.engagementInterface, QIcon(":/images/agreement.png"), 'Interactions Pré-engagement')
        self.addSubInterface(self.scanInterface, QIcon(":/images/scaninterfaceicon.png"), 'Scan - Cible et Reconnaissance')
        self.addSubInterface(self.cibleInterface, QIcon(":/images/cible.png"), 'Scan - Cibles Détectées')
        self.addSubInterface(self.vulnerabiliteInterface, QIcon(":/images/vulnerabilite.png"), 'Exploitation - Vulnérabilitées')
        self.addSubInterface(self.evaluationInterface, QIcon(":/images/strike.png"), 'Exploitation - Evaluation des Vulnérabilités')
        self.navigationInterface.addSeparator()
        self.addSubInterface(self.qemuInterface, QIcon(":/images/kali.png"), 'Kali - Control Center')

        self.navigationInterface.addItem(
            routeKey='price',
            icon=QIcon(":/images/agreement.png"),
            text="Générer un Rapport",
            onClick=self.ReportCreator,
            selectable=False,
            tooltip="Génère un rapport",
            position=NavigationItemPosition.BOTTOM
        )

        self.scanInterface.boutonprofilecreation.clicked.connect(self.profiles_creation)
        self.scanInterface.chargementprofile.clicked.connect(self.chargement_profile)
        self.scanInterface.lancementscan.clicked.connect(self.lancer_scan)
        self.cibleInterface.scanvulnerabilite.clicked.connect(self.vulnerabilite_scan)

        self.evaluationInterface.passwordchecker.textChanged.connect(self.check_strength)
        self.evaluationInterface.hydraexecution.clicked.connect(self.hydra_lancement)

        self.profiles_initialisation()

        #self.cibleInterface.cibletable()

    def profiles_initialisation(self):
        print("profile_initialisation")
        profiles = self.profile_manager.list_profiles()
        self.scanInterface.loadprofile.clear()
        if profiles:
            self.scanInterface.loadprofile.addItems(profiles)

    def profiles_creation(self):
        print("création du profile")
        profile = self.scanInterface.createprofile.text()

        if not profile:
            print("Aucun text entrée")
            return
        if profile in self.profile_manager.list_profiles():
            print("Profile déjà existant")
            return
        
        variables = {}
        self.profile_manager.save_profile(variables,profile)
        self.profiles_initialisation()
        print("Profil créer avec succès")
        

    def chargement_profile(self):
        print("chargement du profile")
        selected_profile = self.scanInterface.loadprofile.currentText()
        if selected_profile:
            self.scanInterface.actualprofile.setText(selected_profile)

            # Partie cible sous-réseau
            reseau_cible = self.profile_manager.load_variable(selected_profile, "reseau_cible")
            if reseau_cible is not None:
                self.scanInterface.sousreseau.setText(str(reseau_cible))
            else:
                self.scanInterface.sousreseau.clear()

            # Partie cibles détetées
            cible_detecte = self.profile_manager.load_variable(selected_profile, "cible_detecte")
            if cible_detecte is not None:
                self.cibleInterface.cibletable(scan_results=cible_detecte)
            else:
                self.cibleInterface.cibledetecte.clear()

            # Partie vulnérabilités détectés
            vulnerabilite_detecte = self.profile_manager.load_variable(selected_profile, "vulnerabilite_detecte")
            if vulnerabilite_detecte is not None:
                self.vulnerabiliteInterface.chargement_vulnerabilite(vulnerabilite_results=vulnerabilite_detecte)
            else:
                self.vulnerabiliteInterface.clear_vulnerabilite()

            # Chargement des cibles Hydra si disponible
            cible_21 = set()
            vulnerabilite_cible = self.profile_manager.load_variable(selected_profile, "vulnerabilite_detecte")

            if vulnerabilite_cible is not None:
                for item in vulnerabilite_cible:
                    if item['Port'] == '21':
                        cible_21.add(item['IP'])
            else:
                cible_21 = []
            
            hydra_cibles = list(cible_21)
            self.evaluationInterface.hydracomboboxtarget.clear()
            self.evaluationInterface.hydracomboboxtarget.addItems(hydra_cibles)

        else:
            print("Aucun profile sélectionné")

    def ReportCreator(self):
        selected_profile = self.scanInterface.actualprofile.text()
        generer_pdf = RapportGenerateur(Profile)
        if selected_profile:
            generer_pdf.GenererRapport(Profile=selected_profile)
        else:
            print("Aucun profil")

    def lancer_scan(self):
        if self.scanInterface.actualprofile.text():
            selected_profile = self.scanInterface.loadprofile.currentText()
            cible = self.scanInterface.sousreseau.text()

            self.worker = Worker(self.automatisation.lancement_scan, sousreseau=cible, optionscan=1)
            self.worker.result.connect(lambda result, cible=cible: self.scan_finished(selected_profile, cible, result))
            self.worker.finished.connect(self.worker.deleteLater)

            self.worker.start()
        else:
            print("Aucun profile sélectionné ou chargé")



    def scan_finished(self, selected_profile, cibles, result):
        if result:   
            self.profile_manager.add_or_update_variable(selected_profile, "reseau_cible", cibles)
        else:
            ip_address, cidr = self.automatisation.get_network_interface_info()
            result = ip_address + "/" + cidr
            self.profile_manager.add_or_update_variable(selected_profile, "reseau_cible", cibles)
        
        # Update the detected targets in the profile
        self.profile_manager.add_or_update_variable(selected_profile, "cible_detecte", result)

        print(result)

        self.scanInterface.sousreseau.setText(str(cibles))

        # Update the interface with the scan results
        self.cibleInterface.cibletable(scan_results=result)

        # Switch to the cibleInterface after processing the scan results
        SplitFluentWindow.switchTo(self, interface=self.cibleInterface)

    def vulnerabilite_scan(self):
        cible_table = self.cibleInterface.TableContents()
        vulnerabilite = self.gvm_management.scan_vulnerabilite(cible_table)
        print(vulnerabilite)
        SplitFluentWindow.switchTo(self, interface=self.vulnerabiliteInterface)


    def vulnerabilite_scan_finished(self, vulnerabilite):
        # Handle the vulnerability scan result
        print("Vulnerability scan result:", vulnerabilite)
        # Update the interface with the vulnerability scan results
        self.vulnerabiliteInterface.update_vulnerabilities(vulnerabilite)
        # Switch to the vulnerability interface after processing the scan results
        SplitFluentWindow.switchTo(self, interface=self.vulnerabiliteInterface)


    def printtable(self):
        cible_table = self.cibleInterface.TableContents()
        print(cible_table)


    def liveupdate(self, livedata):
        self.cibleInterface.liveupdate(livedata)

    def check_strength(self):
        password = self.evaluationInterface.passwordchecker.text()
        self.evaluationInterface.complexitevisuel.setVisible(True)

        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)

        if len(password) < 8 or not (has_upper and has_lower and has_digit and has_special):
            strength = "Faible"
            self.evaluationInterface.complexitevisuel.setStyleSheet("background-color: red")
        elif len(password) < 10:
            strength = "Moyen"
            self.evaluationInterface.complexitevisuel.setStyleSheet("background-color: orange")
        else:
            strength = "Fort"
            self.evaluationInterface.complexitevisuel.setStyleSheet("background-color: green")

        self.evaluationInterface.complexitepassword.setText(f"Complexité du mot de passe : {strength}")

    def hydra_lancement(self):
        hydra_cible = self.evaluationInterface.hydracomboboxtarget.currentText()
        self.evaluationInterface.hydra_progressbar.setVisible(True)

        command = f"cd passwords-and-usernames && hydra -L top-usernames-shortlist.txt -P xato-net-10-million-passwords-10.txt {hydra_cible} ftp"
        self.worker = SSHWorker(command=command)
        self.worker.update_signal.connect(self.evaluationInterface.evaluationterminal.append)
        self.worker.finished_signal.connect(self.on_hydra_completion)  # Connect to slot for completion
        self.worker.start()

    def on_hydra_completion(self):
        hydra_resultat = self.worker.output  # Access the output attribute
        selected_profile = self.scanInterface.loadprofile.currentText()
        self.profile_manager.add_or_update_variable(selected_profile, "hydra_resultat", hydra_resultat)
        print("Hydra command output:", hydra_resultat)
        self.evaluationInterface.hydra_progressbar.setVisible(False)


    def closeEvent(self, event):
        # Handle the close event
        reply = QMessageBox.question(self, 'Message',
            "Etes vous sûr de vouloir fermer la PenToolBox ?", QMessageBox.Yes |
            QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            event.accept()
            self.qemu_manager.terminate_qemu()
            if self.worker and self.worker.isRunning():
                self.worker.finished.connect(lambda: self.worker.deleteLater())  # Wait for the worker to finish before deleting
                self.worker.stop()  # Stop the worker
            else:
                QApplication.quit()
        else:
            event.ignore()



if __name__ == '__main__':
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps)

    app = QApplication(sys.argv)
    w = main()
    w.show()
    sys.exit(app.exec_())