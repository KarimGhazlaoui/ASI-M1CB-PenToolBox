# coding:utf-8
import sys

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication, QWidget

from qfluentwidgets import SplitFluentWindow, FluentIcon

from app.interface.scan_interface import ScanInterface
from app.interface.engagement_interface import EngagementInterface
from app.interface.cible_interface import CibleInterface
from app.interface.qemu_interface import QemuInterface

from app.scripts.qemu_script import QemuManager

from app.engagement import CustomMessageBox

from app.automatisation import scan_vers_cible

import app.resource.resource_rc

class main(SplitFluentWindow):

    def __init__(self, parent=None):
        super().__init__(parent=parent)

        #CustomMessageBox(self)

        #QemuManager.start_qemu(self)

        self.resize(1416, 858)
        self.setWindowTitle("KGB - PenToolBox")
        self.setWindowIcon(QIcon(':/images/logo.png'))

        self.scanInterface = ScanInterface(self)
        #self.engagementInterface = EngagementInterface(self)
        self.cibleInterface = CibleInterface(self)
        self.qemuInterface = QemuInterface(self)

        #self.addSubInterface(self.engagementInterface, QIcon(":/images/agreement.png"), 'Interactions Pré-engagement')
        self.addSubInterface(self.scanInterface, QIcon(":/images/scaninterfaceicon.png"), 'Scan - Reconnaissance')
        self.addSubInterface(self.cibleInterface, QIcon(":/images/cible.png"), 'Scan - Cibles Détectées')

        self.addSubInterface(self.qemuInterface, QIcon(":/images/kali.png"), 'Kali - Control Center')

        self.scanInterface.lancementscan.clicked.connect(self.lancer_scan)

        

        #self.cibleInterface.cibletable()
        
    def lancer_scan(self):
        print("lancement scan")
        scan = scan_vers_cible()
        cibles = scan.lancement_scan(sousreseau=self.scanInterface.sousreseau.text(), optionscan=1)
        print("lancer_scan value :" + str(cibles))
        self.cibleInterface.cibletable(scan_results=cibles)

if __name__ == '__main__':
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps)

    app = QApplication(sys.argv)
    w = main()
    w.show()
    app.exec_()