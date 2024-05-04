# coding:utf-8
import sys

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication, QWidget, QMessageBox

from qfluentwidgets import SplitFluentWindow, FluentIcon, Flyout, InfoBarIcon, FlyoutAnimationType, MessageBox

from app.interface.scan_interface import ScanInterface
from app.interface.engagement_interface import EngagementInterface
from app.interface.cible_interface import CibleInterface
from app.interface.vulnerabilite_interface import VulnerabiliteInterface
from app.interface.qemu_interface import QemuInterface

from app.scripts.qemu_script import QemuManager

from app.engagement import CustomMessageBox

from app.automatisation import scan_vers_cible
from app.scripts.qemu_script import QemuManager

import app.resource.resource_rc

class main(SplitFluentWindow):

    automatisation = scan_vers_cible()

    def __init__(self, parent=None):
        super().__init__(parent=parent)

        #CustomMessageBox(self)

        self.qemu_manager = QemuManager()
        self.qemu_manager.start_qemu()

        self.resize(1767, 1083)
        self.setWindowTitle("KGB - PenToolBox")
        self.setWindowIcon(QIcon(':/images/logo.png'))

        self.scanInterface = ScanInterface(self)
        #self.engagementInterface = EngagementInterface(self)
        self.cibleInterface = CibleInterface(self)
        self.vulnerabiliteInterface = VulnerabiliteInterface(self)
        self.qemuInterface = QemuInterface(self)

        #self.addSubInterface(self.engagementInterface, QIcon(":/images/agreement.png"), 'Interactions Pré-engagement')
        self.addSubInterface(self.scanInterface, QIcon(":/images/scaninterfaceicon.png"), 'Scan - Reconnaissance')
        self.addSubInterface(self.cibleInterface, QIcon(":/images/cible.png"), 'Scan - Cibles Détectées')
        self.addSubInterface(self.vulnerabiliteInterface, QIcon(":/images/strike.png"), 'Exploitation - Vulnérabilitées')

        self.addSubInterface(self.qemuInterface, QIcon(":/images/kali.png"), 'Kali - Control Center')

        self.scanInterface.lancementscan.clicked.connect(self.lancer_scan)
        self.cibleInterface.scanvulnerabilite.clicked.connect(self.vers_vulnerabilite_scan)

        

        #self.cibleInterface.cibletable()
        
    def lancer_scan(self):
        print("lancement du scan")
        cibles = self.automatisation.lancement_scan(sousreseau=self.scanInterface.sousreseau.text(), optionscan=1)
        print("lancer_scan value :" + str(cibles))
        self.cibleInterface.cibletable(scan_results=cibles)
        SplitFluentWindow.switchTo(self, interface=self.cibleInterface)

    def vers_vulnerabilite_scan(self):
        cible_table = self.cibleInterface.TableContents()
        vulnerabilite = self.automatisation.scan_vulnerabilite(cible_table)
        print(vulnerabilite)
        SplitFluentWindow.switchTo(self, interface=self.vulnerabiliteInterface)

    def printtable(self):
        cible_table = self.cibleInterface.TableContents()
        print(cible_table)


    def closeEvent(self, event):
        # Handle the close event
        reply = QMessageBox.question(self, 'Message',
            "Etes vous sûr de vouloir fermer la PenToolBox ?", QMessageBox.Yes |
            QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            event.accept()
            self.qemu_manager.terminate_qemu()
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