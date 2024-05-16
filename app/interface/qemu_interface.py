from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout
from qvncwidget import QVNCWidget
from .Ui_QemuInterface import Ui_QemuInterface

class QemuInterface(QWidget, Ui_QemuInterface):

    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.setupUi(self)

    def vnc_start(self):
        # Create a layout for the "QVNC" widget
        layout = QVBoxLayout(self.QVNC)
        #layout.setContentsMargins(0, 0, 0, 0)  # Remove margins
        #layout.setSpacing(0)  # Remove spacing

        # Instantiate QVNCWidget and add it to the layout
        self.vnc_widget = QVNCWidget(self.QVNC, host="127.0.0.1", port=5900, readOnly=False)
        layout.addWidget(self.vnc_widget)  # Add the widget to the layout
        self.vnc_widget.setMouseTracking(False)
        self.vnc_widget.setFocusPolicy(Qt.StrongFocus)  # Set focus policy
        self.vnc_widget.onInitialResize.connect(self.resize)
        self.vnc_widget.start()

    def keyPressEvent(self, ev):
        print("KaliViewerInterface keyPressEvent")
        self.vnc_widget.keyPressEvent(ev)
        super().keyPressEvent(ev)

    def keyReleaseEvent(self, ev):
        print("KaliViewerInterface keyReleaseEvent")
        self.vnc_widget.keyReleaseEvent(ev)
        super().keyReleaseEvent(ev)

    def closeEvent(self, event):
        self.vnc_widget.stop()
        super().closeEvent(event)