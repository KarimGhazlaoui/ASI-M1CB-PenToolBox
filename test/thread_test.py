import sys
import time
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel
from PyQt5.QtCore import QThread, pyqtSignal

class Worker(QThread):
    finished = pyqtSignal()

    def __init__(self):
        super().__init__()

    def run(self):
        # Simulating a time-consuming task
        time.sleep(5)
        self.finished.emit()

class MyWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Non-Freezing GUI Example")
        self.setGeometry(100, 100, 400, 200)

        layout = QVBoxLayout()
        self.label = QLabel("Click the button to start the task")
        layout.addWidget(self.label)

        self.button = QPushButton("Start Task")
        self.button.clicked.connect(self.start_task)
        layout.addWidget(self.button)

        self.setLayout(layout)

    def start_task(self):
        self.label.setText("Task is running... Please wait.")
        self.button.setEnabled(False)

        self.worker = Worker()
        self.worker.finished.connect(self.task_finished)
        self.worker.start()

    def task_finished(self):
        self.label.setText("Task finished!")
        self.button.setEnabled(True)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MyWindow()
    window.show()
    sys.exit(app.exec_())
