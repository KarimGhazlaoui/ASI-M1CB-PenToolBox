import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLineEdit, QLabel
from PyQt5.QtGui import QColor
from PyQt5.QtCore import Qt

class PasswordStrengthChecker(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Password Strength Checker")
        self.setGeometry(100, 100, 300, 200)

        layout = QVBoxLayout()

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter your password")
        self.password_input.textChanged.connect(self.check_strength)

        self.strength_label = QLabel()
        self.strength_label.setAlignment(Qt.AlignCenter)

        self.weak_line = QLabel()
        self.weak_line.setFixedHeight(5)
        self.weak_line.setStyleSheet("background-color: red")
        self.weak_line.setVisible(False)  # Initially hide the weak line

        self.medium_line = QLabel()
        self.medium_line.setFixedHeight(5)
        self.medium_line.setStyleSheet("background-color: orange")
        self.medium_line.setVisible(False)  # Initially hide the medium line

        self.strong_line = QLabel()
        self.strong_line.setFixedHeight(5)
        self.strong_line.setStyleSheet("background-color: green")
        self.strong_line.setVisible(False)  # Initially hide the strong line

        layout.addWidget(self.password_input)
        layout.addWidget(self.strength_label)
        layout.addWidget(self.weak_line)
        layout.addWidget(self.medium_line)
        layout.addWidget(self.strong_line)

        self.setLayout(layout)

    def check_strength(self):
        password = self.password_input.text()

        if len(password) < 6:
            strength = "Weak"
            self.weak_line.setVisible(True)
            self.medium_line.setVisible(False)
            self.strong_line.setVisible(False)
        elif len(password) < 10:
            strength = "Medium"
            self.weak_line.setVisible(False)
            self.medium_line.setVisible(True)
            self.strong_line.setVisible(False)
        else:
            strength = "Strong"
            self.weak_line.setVisible(False)
            self.medium_line.setVisible(False)
            self.strong_line.setVisible(True)

        self.strength_label.setText(f"Password Strength: {strength}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PasswordStrengthChecker()
    window.show()
    sys.exit(app.exec_())
