"""
Sync tab/dialog for the GUI. Deliberately isolated: this is the ONLY
gui/ file that imports anything from sync/, and it does so lazily
(inside methods, not at module import time) so the rest of the GUI
and all of core/ can run with zero network dependency present.
"""

import os

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout, QLineEdit,
    QPushButton, QLabel, QCheckBox, QMessageBox, QTextEdit, QFileDialog,
)
from PyQt6.QtCore import Qt


class SyncDialog(QDialog):
    def __init__(self, parent, vault, sync_settings: dict, on_restore=None):
        """
        sync_settings: mutable dict persisted by the caller across
        dialog opens, e.g. {"enabled": False, "server_url": "...",
        "vault_id": "...", "api_key": "...", "pinned_sig_pub_b64": None,
        "server_storage_dir": "./sync_storage"}

        "api_key" is the per-vault authorization key the server requires
        on every handshake. It can be typed in manually (from
        `python -m sync.manage_access register <vault_id>` run on the
        server), or generated in-app via the "Register / Rotate API Key"
        button below, WHEN the server's storage directory is reachable
        on this machine's filesystem — see that button's docstring.

        on_restore: optional callback, on_restore(restored_db_path),
        invoked if the user chooses to switch into a just-restored
        backup immediately rather than only being told its path.
        """
        super().__init__(parent)
        self.setWindowTitle("Sync Settings")
        self.setMinimumWidth(520)
        self.vault = vault
        self.settings = sync_settings
        self._on_restore = on_restore
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout()

        self.enable_check = QCheckBox("Enable sync (off by default)")
        self.enable_check.setChecked(self.settings.get("enabled", False))
        self.enable_check.toggled.connect(self._on_toggle_enabled)
        layout.addWidget(self.enable_check)

        note = QLabel(
            "Sync is the only networked part of this app. The core vault "
            "never makes network calls, with or without sync enabled."
        )
        note.setWordWrap(True)
        note.setStyleSheet("color: gray; font-size: 11px;")
        layout.addWidget(note)

        form = QFormLayout()
        self.server_url_input = QLineEdit(self.settings.get("server_url", "http://127.0.0.1:8420"))
        form.addRow("Sync server URL:", self.server_url_input)

        self.vault_id_input = QLineEdit(self.settings.get("vault_id", ""))
        self.vault_id_input.setPlaceholderText("e.g. a UUID you choose, identifies this vault to the server")
        form.addRow("Vault ID:", self.vault_id_input)

        self.api_key_input = QLineEdit(self.settings.get("api_key", ""))
        self.api_key_input.setPlaceholderText("Register below, or paste a key generated elsewhere")
        self.api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("API key:", self.api_key_input)

        layout.addLayout(form)

        # --- In-app registration (local filesystem access to the
        # server's storage dir required — see _register_api_key) ---
        reg_row = QHBoxLayout()
        self.storage_dir_input = QLineEdit(self.settings.get("server_storage_dir", "./sync_storage"))
        self.storage_dir_input.setPlaceholderText("Server's storage directory, e.g. ./sync_storage")
        browse_btn = QPushButton("Browse…")
        browse_btn.clicked.connect(self._browse_storage_dir)
        register_btn = QPushButton("Register / Rotate API Key")
        register_btn.clicked.connect(self._register_api_key)
        reg_row.addWidget(self.storage_dir_input)
        reg_row.addWidget(browse_btn)
        reg_row.addWidget(register_btn)
        layout.addLayout(reg_row)

        reg_note = QLabel(
            "Registering here works only if this machine can directly read/write "
            "the SERVER's storage directory (e.g. you're running the server "
            "locally too, or it's on a shared/mounted path) — it does the exact "
            "same thing as running `python -m sync.manage_access register "
            "<vault_id>` in a terminal, just without leaving the app. This must "
            "point at the SAME directory the running server uses "
            "(its PQVAULT_SYNC_STORAGE, default ./sync_storage relative to "
            "wherever the server process was started). If the server is on a "
            "different machine you can't reach this way, register from a "
            "terminal on that machine instead and paste the key above."
        )
        reg_note.setWordWrap(True)
        reg_note.setStyleSheet("color: gray; font-size: 11px;")
        layout.addWidget(reg_note)

        self.pin_status = QLabel(self._pin_status_text())
        self.pin_status.setWordWrap(True)
        self.pin_status.setStyleSheet("color: gray; font-size: 11px;")
        layout.addWidget(self.pin_status)

        forget_pin_btn = QPushButton("Forget pinned server key")
        forget_pin_btn.clicked.connect(self._forget_pin)
        layout.addWidget(forget_pin_btn)

        btn_row = QHBoxLayout()
        self.upload_btn = QPushButton("⬆ Backup now")
        self.upload_btn.clicked.connect(self._do_upload)
        self.download_btn = QPushButton("⬇ Restore from backup…")
        self.download_btn.clicked.connect(self._do_download)
        btn_row.addWidget(self.upload_btn)
        btn_row.addWidget(self.download_btn)
        layout.addLayout(btn_row)

        self.status_output = QTextEdit()
        self.status_output.setReadOnly(True)
        self.status_output.setFixedHeight(100)
        layout.addWidget(self.status_output)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self._on_close)
        layout.addWidget(close_btn)

        self.setLayout(layout)
        self._on_toggle_enabled(self.enable_check.isChecked())

    def _pin_status_text(self) -> str:
        if self.settings.get("pinned_sig_pub_b64"):
            return "Server signing key is pinned (trust-on-first-use already happened)."
        return "No server key pinned yet — first sync will trust-on-first-use and pin it."

    def _forget_pin(self):
        self.settings["pinned_sig_pub_b64"] = None
        self.pin_status.setText(self._pin_status_text())
        self._log("Forgot pinned server key. Next sync will trust-on-first-use again.")

    def _on_toggle_enabled(self, checked: bool):
        self.server_url_input.setEnabled(checked)
        self.vault_id_input.setEnabled(checked)
        self.api_key_input.setEnabled(checked)
        self.storage_dir_input.setEnabled(checked)
        self.upload_btn.setEnabled(checked)
        self.download_btn.setEnabled(checked)

    def _log(self, msg: str):
        self.status_output.append(msg)

    def _browse_storage_dir(self):
        chosen = QFileDialog.getExistingDirectory(
            self, "Select the sync server's storage directory",
            self.storage_dir_input.text().strip() or ".",
        )
        if chosen:
            self.storage_dir_input.setText(chosen)

    def _register_api_key(self):
        # Local import — same module-boundary reasoning as the sync
        # client imports below: this touches sync/ only when the user
        # actually clicks this button, not at dialog-construction time.
        from sync.access_store import VaultAccessStore

        vault_id = self.vault_id_input.text().strip()
        if not vault_id:
            QMessageBox.warning(self, "Missing info", "Enter a Vault ID first.")
            return

        storage_dir = self.storage_dir_input.text().strip()
        if not storage_dir:
            QMessageBox.warning(self, "Missing info", "Enter the server's storage directory first.")
            return

        access_path = os.path.join(storage_dir, "vault_access.json")

        try:
            store = VaultAccessStore(access_path)

            if store.is_registered(vault_id):
                confirm = QMessageBox.question(
                    self, "Already registered",
                    f"Vault ID {vault_id!r} already has an API key registered at "
                    f"this storage directory. Generate a NEW key? This immediately "
                    f"invalidates the old one for any other client using it.",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                )
                if confirm != QMessageBox.StandardButton.Yes:
                    return
                key = store.register(vault_id, overwrite=True)
                self._log(f"Rotated API key for vault_id {vault_id!r}.")
            else:
                key = store.register(vault_id)
                self._log(f"Registered vault_id {vault_id!r} and generated a new API key.")

        except PermissionError as e:
            QMessageBox.critical(
                self, "Registration failed",
                f"Could not register: {e}",
            )
            return
        except OSError as e:
            QMessageBox.critical(
                self, "Registration failed",
                f"Could not reach or write to that storage directory: {e}\n\n"
                f"Check the path and that it matches where the server is "
                f"actually running from — if the server isn't on this machine, "
                f"register from a terminal on that machine instead.",
            )
            return

        self.api_key_input.setText(key)
        self.settings["server_storage_dir"] = storage_dir
        QMessageBox.information(
            self, "Registered",
            "API key generated and filled in above. It's saved with your other "
            "sync settings when you close this dialog.",
        )

    def _build_client(self):
        from sync.client import SyncClient, ServerAuthError, SyncError
        import base64

        vault_id = self.vault_id_input.text().strip()
        if not vault_id:
            raise ValueError("Enter a Vault ID before syncing.")

        api_key = self.api_key_input.text().strip()
        if not api_key:
            raise ValueError(
                "Enter or register an API key for this vault before syncing "
                "(see 'Register / Rotate API Key' above)."
            )

        pinned = None
        if self.settings.get("pinned_sig_pub_b64"):
            pinned = base64.b64decode(self.settings["pinned_sig_pub_b64"])

        return SyncClient(
            base_url=self.server_url_input.text().strip(),
            vault_id=vault_id,
            api_key=api_key,
            pinned_server_sig_pub=pinned,
        )

    def _do_upload(self):
        from sync.client import ServerAuthError, SyncError
        import base64
        try:
            client = self._build_client()
        except ValueError as e:
            QMessageBox.warning(self, "Missing info", str(e))
            return

        try:
            nonce, ciphertext = self.vault.export_backup_blob()
            client.upload_backup(nonce, ciphertext)
            if client.last_seen_server_sig_pub and not self.settings.get("pinned_sig_pub_b64"):
                self.settings["pinned_sig_pub_b64"] = base64.b64encode(client.last_seen_server_sig_pub).decode()
                self.pin_status.setText(self._pin_status_text())
                self._log("Pinned server signing key (trust-on-first-use).")
            self._log(f"Backup uploaded successfully ({len(ciphertext)} bytes).")
        except ServerAuthError as e:
            self._log(f"ABORTED — server authentication failed: {e}")
            QMessageBox.critical(self, "Sync aborted", str(e))
        except SyncError as e:
            self._log(f"Sync failed: {e}")
            QMessageBox.warning(self, "Sync failed", str(e))
        finally:
            client.close()

    def _do_download(self):
        from sync.client import ServerAuthError, SyncError
        confirm = QMessageBox.question(
            self, "Restore from backup",
            "This will download the server's copy and save it as a NEW file "
            "next to your current vault (it will not overwrite your open vault). "
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        try:
            client = self._build_client()
        except ValueError as e:
            QMessageBox.warning(self, "Missing info", str(e))
            return

        try:
            nonce, ciphertext = client.download_backup()
            restore_path = self.vault.storage.db_path + ".restored"
            self.vault.restore_backup_blob(nonce, ciphertext, restore_path)
            self._log(f"Restored backup to: {restore_path}")

            if self._on_restore is not None:
                switch = QMessageBox.question(
                    self, "Restored",
                    f"Backup saved to:\n{restore_path}\n\n"
                    f"Switch to viewing the restored vault now? You'll be asked "
                    f"for your master password again. Your currently open vault "
                    f"file is left unchanged on disk either way.",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                )
                if switch == QMessageBox.StandardButton.Yes:
                    self._on_restore(restore_path)
                    self.accept()
                    return
            else:
                QMessageBox.information(self, "Restored", f"Backup saved to:\n{restore_path}")
        except ServerAuthError as e:
            self._log(f"ABORTED — server authentication failed: {e}")
            QMessageBox.critical(self, "Sync aborted", str(e))
        except SyncError as e:
            self._log(f"Sync failed: {e}")
            QMessageBox.warning(self, "Sync failed", str(e))
        finally:
            client.close()

    def _on_close(self):
        self.settings["enabled"] = self.enable_check.isChecked()
        self.settings["server_url"] = self.server_url_input.text().strip()
        self.settings["vault_id"] = self.vault_id_input.text().strip()
        self.settings["api_key"] = self.api_key_input.text().strip()
        self.settings["server_storage_dir"] = self.storage_dir_input.text().strip()
        self.accept()