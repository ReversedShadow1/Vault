"""
Unlock screen: shown at startup. Handles both "create new vault" and
"unlock existing vault" flows via two explicit entry points, so the
user's intent is always clear rather than inferred purely from whether
a chosen path happens to exist yet.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QFileDialog, QMessageBox, QProgressBar,
)
from PyQt6.QtCore import Qt, pyqtSignal

from core.vault import Vault, WeakPasswordError, WrongPasswordError
from zxcvbn import zxcvbn


DEFAULT_VAULT_PATH = "vault.db"


class UnlockScreen(QWidget):
    """Emits vault_ready(Vault) once the user has successfully unlocked
    or created a vault."""

    vault_ready = pyqtSignal(object)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("PQ Password Vault")
        self.setMinimumWidth(420)
        self._vault_path = DEFAULT_VAULT_PATH
        self._build_ui()
        # On startup, land directly in unlock mode if the default path
        # already has a vault (the common case of reopening the same
        # file), or create mode if it doesn't (the common case of a
        # first run) — this default-path convenience is unchanged from
        # before. The two buttons below are for explicitly choosing a
        # DIFFERENT file for either action.
        self._refresh_mode()

    def _build_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(12)

        title = QLabel("🔒 Post-Quantum Password Vault")
        title.setStyleSheet("font-size: 18px; font-weight: bold;")
        layout.addWidget(title)

        path_row = QHBoxLayout()
        self.path_label = QLabel(self._vault_path)
        self.path_label.setStyleSheet("color: gray;")
        path_row.addWidget(self.path_label, stretch=1)
        layout.addLayout(path_row)

        choose_row = QHBoxLayout()
        open_btn = QPushButton("Open Existing Vault…")
        open_btn.clicked.connect(self._choose_existing_file)
        new_btn = QPushButton("Create New Vault…")
        new_btn.clicked.connect(self._choose_new_file)
        choose_row.addWidget(open_btn)
        choose_row.addWidget(new_btn)
        layout.addLayout(choose_row)

        self.mode_label = QLabel()
        self.mode_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(self.mode_label)

        self.pw_input = QLineEdit()
        self.pw_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw_input.setPlaceholderText("Master password")
        self.pw_input.textChanged.connect(self._on_pw_changed)
        layout.addWidget(self.pw_input)

        self.confirm_input = QLineEdit()
        self.confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_input.setPlaceholderText("Confirm master password")
        layout.addWidget(self.confirm_input)

        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 4)
        self.strength_bar.setTextVisible(False)
        self.strength_bar.setFixedHeight(8)
        layout.addWidget(self.strength_bar)

        self.strength_label = QLabel("")
        self.strength_label.setStyleSheet("color: gray; font-size: 11px;")
        layout.addWidget(self.strength_label)

        self.action_btn = QPushButton("Unlock")
        self.action_btn.clicked.connect(self._on_action)
        layout.addWidget(self.action_btn)

        self.error_label = QLabel("")
        self.error_label.setStyleSheet("color: #c0392b;")
        self.error_label.setWordWrap(True)
        layout.addWidget(self.error_label)

        self.setLayout(layout)
        self.pw_input.returnPressed.connect(self._on_action)

    def _refresh_mode(self):
        probe = Vault(self._vault_path)
        is_existing = probe.storage.is_initialized()
        probe.close()
        self._is_existing = is_existing
        self.path_label.setText(self._vault_path)
        if is_existing:
            self.mode_label.setText("Unlock existing vault")
            self.action_btn.setText("Unlock")
            self.confirm_input.hide()
            self.strength_bar.hide()
            self.strength_label.hide()
        else:
            self.mode_label.setText("Create new vault")
            self.action_btn.setText("Create Vault")
            self.confirm_input.show()
            self.strength_bar.show()
            self.strength_label.show()
        self.error_label.setText("")

    def _choose_existing_file(self):
        """
        Explicit 'open' entry point. QFileDialog.getOpenFileName's
        native picker already only lets the user select a file that
        exists on disk, but that alone doesn't guarantee it's an
        INITIALIZED vault (could be an empty file, or an unrelated
        .db). Checking explicitly here — rather than just letting
        _refresh_mode() silently fall into "create" mode for it — means
        picking the wrong file produces a clear error instead of
        quietly reinterpreting "open" as "create."
        """
        path, _ = QFileDialog.getOpenFileName(
            self, "Open vault file", self._vault_path,
            "Vault files (*.db);;All files (*)",
        )
        if not path:
            return

        probe = Vault(path)
        is_initialized = probe.storage.is_initialized()
        probe.close()

        if not is_initialized:
            QMessageBox.warning(
                self, "Not a vault file",
                f"{path}\n\ndoesn't contain an initialized vault yet. "
                f"Use \u201cCreate New Vault\u2026\u201d if you want to "
                f"create one here.",
            )
            return

        self._vault_path = path
        self._refresh_mode()

    def _choose_new_file(self):
        """
        Explicit 'create' entry point. Lets the user pick any file path
        (existing or not — DontConfirmOverwrite because "overwrite" is
        the wrong framing for a vault file; we check initialization
        state ourselves and give a more specific message). If the
        chosen path already contains an initialized vault, this refuses
        to silently switch into "unlock" mode for it — the user asked
        to create, so a mismatch here should surface as an explicit
        choice ("open it instead, or pick a different name"), not a
        quiet mode change.
        """
        path, _ = QFileDialog.getSaveFileName(
            self, "Create new vault file", self._vault_path,
            "Vault files (*.db);;All files (*)",
            options=QFileDialog.Option.DontConfirmOverwrite,
        )
        if not path:
            return

        probe = Vault(path)
        is_initialized = probe.storage.is_initialized()
        probe.close()

        if is_initialized:
            QMessageBox.warning(
                self, "Vault already exists",
                f"{path}\n\nalready contains a vault. Use \u201cOpen "
                f"Existing Vault\u2026\u201d to unlock it instead, or "
                f"choose a different file name to create a new one.",
            )
            return

        self._vault_path = path
        self._refresh_mode()

    def _on_pw_changed(self, text: str):
        if self._is_existing:
            return
        if not text:
            self.strength_bar.setValue(0)
            self.strength_label.setText("")
            return
        result = zxcvbn(text)
        self.strength_bar.setValue(result["score"])
        labels = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]
        self.strength_label.setText(labels[result["score"]])

    def _on_action(self):
        self.error_label.setText("")
        password = self.pw_input.text()
        if not password:
            self.error_label.setText("Enter a master password.")
            return

        vault = Vault(self._vault_path)
        if self._is_existing:
            try:
                vault.unlock(password)
            except WrongPasswordError as e:
                self.error_label.setText(str(e))
                vault.close()
                return
        else:
            if password != self.confirm_input.text():
                self.error_label.setText("Passwords do not match.")
                vault.close()
                return
            try:
                vault.create(password)
            except WeakPasswordError as e:
                self.error_label.setText(str(e))
                vault.close()
                return
            except RuntimeError as e:
                # Defensive: _choose_new_file() already checked this
                # path wasn't an initialized vault, but something else
                # could have created one at the same path in the
                # meantime (another instance of this app, etc.).
                self.error_label.setText(str(e))
                vault.close()
                return

        self.pw_input.clear()
        self.confirm_input.clear()
        self.vault_ready.emit(vault)