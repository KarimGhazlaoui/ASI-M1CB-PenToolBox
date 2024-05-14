from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QPixmap, QPainter, QColor, QIcon, QFont
from PyQt5.QtWidgets import QWidget, QTableWidgetItem

from qfluentwidgets import FluentIcon as FIF, InfoBarIcon
from .Ui_VulnerabiliteInterface import Ui_VulnerabiliteInterface

class VulnerabiliteInterface(QWidget, Ui_VulnerabiliteInterface):

    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.setupUi(self)

        self.table_widget = self.vulnerabilitetable


    def chargement_vulnerabilite(self, parent=None, vulnerabilite_results=None):
        self.table_widget.setColumnCount(6)
        self.table_widget.setHorizontalHeaderLabels(["IP", "Port", "Protocole", "Sévérité", "NVT", "CVE"])

        self.table_widget.setRowCount(len(vulnerabilite_results))

        for row, result in enumerate(vulnerabilite_results):
            self.table_widget.setItem(row, 0, QTableWidgetItem(result['IP']))
            self.table_widget.setItem(row, 1, QTableWidgetItem(result['Port']))
            self.table_widget.setItem(row, 2, QTableWidgetItem(result['Protocole']))
            self.table_widget.setItem(row, 4, QTableWidgetItem(result['NVT']))
            self.table_widget.setItem(row, 5, QTableWidgetItem(result['CVE']))

            severity_item = QTableWidgetItem(result['Sévérité'])
            self.table_widget.setItem(row, 3, severity_item)

            severity_item = self.table_widget.item(row, 3)
            severity_level = result['Sévérité']
            if severity_level == 'Low':
                severity_item.setBackground(QColor("green"))
            elif severity_level == 'Medium':
                severity_item.setBackground(QColor("orange"))
            elif severity_level == 'High':
                severity_item.setBackground(QColor("red"))

        self.table_widget.resizeColumnsToContents()  # Resize columns based on content

    def clear_vulnerabilite(self, parent=None):
        self.table_widget.setRowCount(0)
        self.table_widget.setColumnCount(0)