from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QPixmap, QPainter, QColor
from PyQt5.QtWidgets import QWidget

from qfluentwidgets import FluentIcon as FIF, InfoBarIcon
from .Ui_EngagementInterface import Ui_EngagementInterface

class EngagementInterface(QWidget, Ui_EngagementInterface):

    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.setupUi(self)