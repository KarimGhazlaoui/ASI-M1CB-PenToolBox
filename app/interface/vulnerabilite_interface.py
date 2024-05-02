from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QPixmap, QPainter, QColor, QIcon
from PyQt5.QtWidgets import QWidget, QTableWidgetItem

from qfluentwidgets import FluentIcon as FIF, InfoBarIcon
from .Ui_VulnerabiliteInterface import Ui_VulnerabiliteInterface

class VulnerabiliteInterface(QWidget, Ui_VulnerabiliteInterface):

    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.setupUi(self)