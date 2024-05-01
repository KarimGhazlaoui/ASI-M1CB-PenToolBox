from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QPixmap, QPainter, QColor, QIcon
from PyQt5.QtWidgets import QWidget, QTableWidgetItem

from qfluentwidgets import FluentIcon as FIF, InfoBarIcon
from .Ui_CibleInterface import Ui_CibleInterface

class CibleInterface(QWidget, Ui_CibleInterface):

    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.setupUi(self)

    def cibletable(self, parent=None, scan_results=None):

        print("cibletable value :" + str(scan_results))

        if scan_results == None:
            print("Liste vide")
        else:
            print(scan_results)
            print("cibletable en cours")

            table = self.cibledetecte
            table.setBorderVisible(True)
            table.setBorderRadius(8)

            table.setWordWrap(True)
            table.setRowCount(len(scan_results))
            table.setColumnCount(2)


            # Add table data

            for i, cible in enumerate(scan_results):
                for j in range(2):
                    table.setItem(i, j, QTableWidgetItem(cible[j]))

            # Set horizontal header and hide vertical header
            table.setHorizontalHeaderLabels(['IP', 'Status'])
            table.verticalHeader().hide()
