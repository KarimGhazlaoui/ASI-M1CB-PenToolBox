from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QPixmap, QPainter, QColor
from PyQt5.QtWidgets import QWidget

from qfluentwidgets import FluentIcon as FIF, InfoBarIcon
from .Ui_StopWatchInterface import Ui_StopWatchInterface

class StopWatchInterface(QWidget, Ui_StopWatchInterface):

    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.setupUi(self)

        self.flagButton.setIcon(FIF.FLAG)
        self.startButton.setIcon(FIF.POWER_BUTTON)
        self.restartButton.setIcon(FIF.CANCEL)