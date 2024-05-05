# coding:utf-8
import sys

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QStackedWidget

# Import the Ui_CibleInterface2 class directly from the UI file
from app.interface.Ui_CibleInterface2 import Ui_CibleInterface2


class Demo(QWidget):
    def __init__(self):
        super().__init__()

        # Create an instance of the UI class
        self.ui = Ui_CibleInterface2()
        # Set up the UI
        self.ui.setupUi(self)

        # Create a stacked widget to manage switching between interfaces
        self.stackedWidget = QStackedWidget(self)
        self.ui.verticalLayout.addWidget(self.stackedWidget)

        # Add the interfaces to the stacked widget
        self.stackedWidget.addWidget(self.ui.frame)  # Add the QTableWidget to the stacked widget
        self.stackedWidget.addWidget(self.ui.reseauciblecard)

        # Connect the pivot to switch to the QTableWidget when required
        self.ui.Pivot.currentChanged.connect(self.onPivotCurrentChanged)

        # Initially show the QTableWidget
        self.ui.Pivot.setCurrentIndex(0)

    def onPivotCurrentChanged(self, index):
        # Switch to the corresponding interface based on the pivot index
        self.stackedWidget.setCurrentIndex(index)


if __name__ == '__main__':
    # enable dpi scale
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps)

    app = QApplication(sys.argv)
    w = Demo()
    w.show()
    sys.exit(app.exec_())
