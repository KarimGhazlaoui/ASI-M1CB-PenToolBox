from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QPixmap, QPainter, QColor
from PyQt5.QtWidgets import QWidget

from qfluentwidgets import FluentIcon as FIF, InfoBarIcon
from .Ui_FocusInterface import Ui_FocusInterface

class FocusInterface(QWidget, Ui_FocusInterface):

    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.setupUi(self)

        self.pinButton.setIcon(FIF.PIN)
        self.moreButton.setIcon(FIF.MORE)
        self.editButton.setIcon(FIF.EDIT)
        self.addTaskButton.setIcon(FIF.ADD)
        self.moreTaskButton.setIcon(FIF.MORE)
        self.taskIcon1.setIcon(InfoBarIcon.SUCCESS)
        self.taskIcon2.setIcon(InfoBarIcon.WARNING)
        self.taskIcon3.setIcon(InfoBarIcon.WARNING)
        self.startFocusButton.setIcon(FIF.POWER_BUTTON)