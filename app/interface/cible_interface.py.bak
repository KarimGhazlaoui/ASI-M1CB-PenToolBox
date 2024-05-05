from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QPixmap, QPainter, QColor, QIcon
from PyQt5.QtWidgets import QWidget, QTableWidgetItem

from qfluentwidgets import FluentIcon as FIF, InfoBarIcon
from .Ui_CibleInterface import Ui_CibleInterface

class CibleInterface(QWidget, Ui_CibleInterface):

    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.setupUi(self)
        self.table = self.cibledetecte

    def cibletable(self, parent=None, scan_results=None):

        print("cibletable value :" + str(scan_results))

        if scan_results == None:
            print("Liste vide")
        else:
            print(scan_results)
            print("cibletable en cours")

            self.table.setBorderVisible(True)
            self.table.setBorderRadius(8)

            self.table.setWordWrap(True)
            self.table.setRowCount(len(scan_results))
            self.table.setColumnCount(2)


            # Add table data

            for i, cible in enumerate(scan_results):
                for j in range(2):
                    self.table.setItem(i, j, QTableWidgetItem(cible[j]))

            # Set horizontal header and hide vertical header
            self.table.setHorizontalHeaderLabels(['IP', 'Status'])
            self.table.verticalHeader().hide()
    
    def TableContents(self):
        table_adresse = []
        selectedRows = self.table.selectedItems()
        if len(selectedRows) == 0:  # If no row selected, print every first column
            for row in range(self.table.rowCount()):
                item = self.table.item(row, 0)  # Accessing only the first column
                table_adresse.append(item.text())
            return table_adresse
        else:  # If row(s) selected, print only selected row(s) first column
            selectedRowsSet = set([item.row() for item in selectedRows])
            for row in selectedRowsSet:
                item = self.table.item(row, 0)  # Accessing only the first column
                table_adresse.append(item.text())
            return table_adresse

