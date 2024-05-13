from PyQt5.QtWidgets import QApplication, QLabel
from PyQt5.QtCore import QTimer

class MyGUI:
    def __init__(self):
        self.counter = 0
        self.timer = QTimer()
        self.timer.timeout.connect(self.do_something)
        self.setup_gui()

    def setup_gui(self):
        self.app = QApplication([])

        self.label = QLabel("Hello")
        self.label.show()

        self.timer.start(100)  # Repeat every 1000 milliseconds (1 second)

        self.app.exec_()

    def do_something(self):
        print("Repeated action")
        self.counter += 1
        if self.counter >= 10:
            self.timer.stop()
            print("Timer stopped")

if __name__ == "__main__":
    MyGUI()
