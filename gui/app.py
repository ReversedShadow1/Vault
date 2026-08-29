#!/usr/bin/env python3
"""
Week 2 deliverable: functional standalone PyQt6 vault app.

Run: python3 gui/app.py
(Requires a display; set QT_QPA_PLATFORM=offscreen for headless testing.)
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt6.QtWidgets import QApplication

from gui.unlock_screen import UnlockScreen
from gui.main_window import MainWindow


class App:
    def __init__(self):
        self.qapp = QApplication(sys.argv)
        self.unlock_screen = None
        self.main_window = None
        self._show_unlock_screen()

    def _show_unlock_screen(self):
        self.main_window = None
        self.unlock_screen = UnlockScreen()
        self.unlock_screen.vault_ready.connect(self._on_vault_ready)
        self.unlock_screen.show()

    def _on_vault_ready(self, vault):
        self.unlock_screen.close()
        self.unlock_screen = None
        self.main_window = MainWindow(vault, on_lock=self._on_vault_locked)
        self.main_window.show()

    def _on_vault_locked(self):
        if self.main_window is not None:
            self.main_window.vault.close()
            self.main_window.close()
            self.main_window = None
        self._show_unlock_screen()

    def run(self):
        return self.qapp.exec()


def main():
    app = App()
    sys.exit(app.run())


if __name__ == "__main__":
    main()
