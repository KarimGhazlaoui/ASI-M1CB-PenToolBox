from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget
from .Ui_ScanInterface import Ui_ScanInterface

from app.automatisation import scan_vers_cible

class ScanInterface(QWidget, Ui_ScanInterface):

    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.setupUi(self)

        self.furtif.stateChanged.connect(self.on_furtif_state_changed)
        self.agressif.stateChanged.connect(self.on_agressif_state_changed)

        #self.lancementscan.clicked.connect(lambda: self.lancer_scan())

    def on_furtif_state_changed(self, state):
        if state == Qt.Checked:
            self.agressif.setChecked(False)

    def on_agressif_state_changed(self, state):
        if state == Qt.Checked:
            self.furtif.setChecked(False)

    def lancer_scan(self):
        scan = scan_vers_cible(self)
        scan.lancement_scan(sousreseau=self.sousreseau.text(), optionscan=1)