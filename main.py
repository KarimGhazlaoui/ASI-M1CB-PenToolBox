# coding:utf-8
import sys

from PyQt5.QtCore import QObject, Qt, QThread, pyqtSignal
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication, QWidget, QMessageBox

from qfluentwidgets import SplitFluentWindow, FluentIcon, Flyout, InfoBarIcon, FlyoutAnimationType, MessageBox

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

        #self.addSubInterface(self.engagementInterface, QIcon(":/images/agreement.png"), 'Interactions Pré-engagement')
        self.addSubInterface(self.scanInterface, QIcon(":/images/scaninterfaceicon.png"), 'Scan - Cible et Reconnaissance')
        self.addSubInterface(self.cibleInterface, QIcon(":/images/cible.png"), 'Scan - Cibles Détectées')
        self.addSubInterface(self.vulnerabiliteInterface, QIcon(":/images/vulnerabilite.png"), 'Exploitation - Vulnérabilitées')
        self.addSubInterface(self.evaluationInterface, QIcon(":/images/strike.png"), 'Exploitation - Evaluation des Vulnérabilités')

        self.addSubInterface(self.qemuInterface, QIcon(":/images/kali.png"), 'Kali - Control Center')

        self.scanInterface.boutonprofilecreation.clicked.connect(self.profiles_creation)
        self.scanInterface.chargementprofile.clicked.connect(self.chargement_profile)
        self.scanInterface.lancementscan.clicked.connect(self.lancer_scan)
        self.cibleInterface.scanvulnerabilite.clicked.connect(self.vulnerabilite_scan)

        self.evaluationInterface.passwordchecker.textChanged.connect(self.check_strength)

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
        else:
            print("Aucun profile sélectionné")


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