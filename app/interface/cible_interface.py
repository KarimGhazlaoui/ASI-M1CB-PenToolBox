from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QPixmap, QPainter, QColor, QFont, QBrush
from PyQt5.QtWidgets import QWidget, QTableWidgetItem, QProgressBar

from qfluentwidgets import FluentIcon as FIF, InfoBarIcon
from .Ui_CibleInterface import Ui_CibleInterface

class CibleInterface(QWidget, Ui_CibleInterface):

    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.setupUi(self)
        self.table = self.cibledetecte
        self.table2 = self.vulnerabilitetablelive

    def cibletable(self, parent=None, scan_results=None):

        print("cibletable :" + str(scan_results))

        if scan_results == None:
            print("Liste vide")
        else:
            print(scan_results)
            print("cibletable en cours")

            self.table.setBorderVisible(True)
            self.table.setBorderRadius(8)

            self.table.setWordWrap(True)
            self.table.setRowCount(len(scan_results))
            self.table.setColumnCount(3)


            # Ajouter des données à la table

            for i, cible in enumerate(scan_results):
                for j in range(3):
                    self.table.setItem(i, j, QTableWidgetItem(cible[j]))

            # Définir l'en-tête horizontale et masquer l'en-tête verticale
            self.table.setHorizontalHeaderLabels(['IP', 'FQDN', 'Status'])
            self.table.verticalHeader().hide()
    
    def TableContents(self):
        table_adresse = []
        selectedRows = self.table.selectedItems()
        if len(selectedRows) == 0:  # Si aucune ligne n'est sélectionnée, imprimer chaque première colonne
            for row in range(self.table.rowCount()):
                item = self.table.item(row, 0)  # Accéder uniquement à la première colonne
                table_adresse.append(item.text())
            return table_adresse
        else:  # Si une ou plusieurs lignes sont sélectionnées, imprimer uniquement la première colonne des lignes sélectionnées
            selectedRowsSet = set([item.row() for item in selectedRows])
            for row in selectedRowsSet:
                item = self.table.item(row, 0)  # Accéder uniquement à la première colonne
                table_adresse.append(item.text())
            return table_adresse
        
    def liveupdate(self, livedata):
        actualdata = self.vulnerabilitelive.toPlainText()
        if actualdata:
            updatelive = actualdata + '\n' + livedata
        else:
            updatelive = livedata
        updatelive = updatelive.replace("command completed", "")
        self.vulnerabilitelive.setText(updatelive)

    def gvm_progress_table(self, liveprogress):

        task_id, status, progression = liveprogress
        
        # Mettre à jour l'ID de la tâche
        task_id_item = QTableWidgetItem(task_id)
        task_id_item.setTextAlignment(Qt.AlignCenter)
        self.table2.setItem(0, 0, task_id_item)

        bold_font = QFont()
        bold_font.setBold(True)
        
        # Mettre à jour le STATUT et définir sa couleur
        status_item = QTableWidgetItem(status)
        status_item.setTextAlignment(Qt.AlignCenter)
        status_item.setFont(bold_font)
        if status == 'Requested' or status == 'Queued':
            status_item.setBackground(QColor('orange'))
        elif status == 'Running':
            status_item.setBackground(QColor('green'))
            status_item.setForeground(QBrush(QColor('white')))
        elif status == 'Done':
            status_item.setBackground(QColor('blue'))
            status_item.setForeground(QBrush(QColor('white')))
        self.table2.setItem(0, 1, status_item)
        
        # Mettre à jour la PROGRESSION avec une barre de progression
        progress_bar = QProgressBar()
        progress_bar.setValue(progression)
        self.table2.setCellWidget(0, 2, progress_bar)
        # Centrer la barre de progression dans la cellule
        self.table2.setColumnWidth(2, 150)  # Ajuster la largeur de la colonne pour s'adapter à la barre de progression
        progress_bar.setAlignment(Qt.AlignCenter)  # Centrer le texte de la barre de progression