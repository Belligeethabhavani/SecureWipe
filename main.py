import sys
import os

# Make sure Python can find our modules when run from the project root
sys.path.insert(0, os.path.dirname(__file__))

from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QIcon

from gui.main_window import MainWindow
from gui.stylesheet import STYLESHEET


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("SecureWipe")
    app.setApplicationVersion("2.0")
    app.setOrganizationName("SecureWipe")
    app.setStyleSheet(STYLESHEET)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
