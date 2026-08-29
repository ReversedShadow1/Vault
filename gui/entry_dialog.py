from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout, QLineEdit,
    QTextEdit, QPushButton, QProgressBar, QLabel, QCheckBox, QSpinBox,
)
from PyQt6.QtCore import Qt
from zxcvbn import zxcvbn

from core.vault import Entry
from core.password_generator import generate_password


class EntryDialog(QDialog):
    def __init__(self, parent=None, entry: Entry | None = None):
        super().__init__(parent)
        self.setWindowTitle("Edit Entry" if entry else "Add Entry")
        self.setMinimumWidth(420)
        self._entry = entry
        self._build_ui()
        if entry:
            self.site_input.setText(entry.site)
            self.username_input.setText(entry.username)
            self.password_input.setText(entry.password)
            self.notes_input.setPlainText(entry.notes)

    def _build_ui(self):
        layout = QVBoxLayout()
        form = QFormLayout()

        self.site_input = QLineEdit()
        form.addRow("Site / Service:", self.site_input)

        self.username_input = QLineEdit()
        form.addRow("Username:", self.username_input)

        pw_row = QHBoxLayout()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.textChanged.connect(self._update_strength)
        self.show_pw_btn = QPushButton("👁")
        self.show_pw_btn.setFixedWidth(32)
        self.show_pw_btn.setCheckable(True)
        self.show_pw_btn.toggled.connect(self._toggle_pw_visibility)
        gen_btn = QPushButton("Generate")
        gen_btn.clicked.connect(self._open_generator)
        pw_row.addWidget(self.password_input)
        pw_row.addWidget(self.show_pw_btn)
        pw_row.addWidget(gen_btn)
        form.addRow("Password:", pw_row)

        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 4)
        self.strength_bar.setTextVisible(False)
        self.strength_bar.setFixedHeight(6)
        form.addRow("Strength:", self.strength_bar)

        self.notes_input = QTextEdit()
        self.notes_input.setFixedHeight(80)
        form.addRow("Notes:", self.notes_input)

        layout.addLayout(form)

        btn_row = QHBoxLayout()
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        save_btn = QPushButton("Save")
        save_btn.setDefault(True)
        save_btn.clicked.connect(self.accept)
        btn_row.addStretch()
        btn_row.addWidget(cancel_btn)
        btn_row.addWidget(save_btn)
        layout.addLayout(btn_row)

        self.setLayout(layout)

    def _toggle_pw_visibility(self, checked: bool):
        self.password_input.setEchoMode(
            QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
        )

    def _update_strength(self, text: str):
        if not text:
            self.strength_bar.setValue(0)
            return
        result = zxcvbn(text)
        self.strength_bar.setValue(result["score"])

    def _open_generator(self):
        dlg = PasswordGeneratorDialog(self)
        if dlg.exec():
            self.password_input.setText(dlg.generated_password)

    def get_entry(self) -> Entry:
        return Entry(
            site=self.site_input.text().strip(),
            username=self.username_input.text().strip(),
            password=self.password_input.text(),
            notes=self.notes_input.toPlainText().strip(),
            entry_id=self._entry.entry_id if self._entry else None,
        )


class PasswordGeneratorDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Generate Password")
        self.generated_password = ""  # nosec B105 — initial empty placeholder, not a credential
        self._build_ui()
        self._regenerate()

    def _build_ui(self):
        layout = QVBoxLayout()

        self.result_display = QLineEdit()
        self.result_display.setReadOnly(True)
        layout.addWidget(self.result_display)

        len_row = QHBoxLayout()
        len_row.addWidget(QLabel("Length:"))
        self.length_spin = QSpinBox()
        self.length_spin.setRange(8, 64)
        self.length_spin.setValue(20)
        self.length_spin.valueChanged.connect(self._regenerate)
        len_row.addWidget(self.length_spin)
        layout.addLayout(len_row)

        self.upper_check = QCheckBox("Uppercase (A-Z)")
        self.upper_check.setChecked(True)
        self.upper_check.toggled.connect(self._regenerate)
        layout.addWidget(self.upper_check)

        self.digits_check = QCheckBox("Digits (0-9)")
        self.digits_check.setChecked(True)
        self.digits_check.toggled.connect(self._regenerate)
        layout.addWidget(self.digits_check)

        self.symbols_check = QCheckBox("Symbols (!@#...)")
        self.symbols_check.setChecked(True)
        self.symbols_check.toggled.connect(self._regenerate)
        layout.addWidget(self.symbols_check)

        regen_btn = QPushButton("Regenerate")
        regen_btn.clicked.connect(self._regenerate)
        layout.addWidget(regen_btn)

        btn_row = QHBoxLayout()
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        use_btn = QPushButton("Use this password")
        use_btn.setDefault(True)
        use_btn.clicked.connect(self.accept)
        btn_row.addStretch()
        btn_row.addWidget(cancel_btn)
        btn_row.addWidget(use_btn)
        layout.addLayout(btn_row)

        self.setLayout(layout)

    def _regenerate(self):
        self.generated_password = generate_password(
            length=self.length_spin.value(),
            use_upper=self.upper_check.isChecked(),
            use_digits=self.digits_check.isChecked(),
            use_symbols=self.symbols_check.isChecked(),
        )
        self.result_display.setText(self.generated_password)
