from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget
from .Ui_EvaluationInterface import Ui_EvaluationInterface

class EvaluationInterface(QWidget, Ui_EvaluationInterface):

    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.setupUi(self)