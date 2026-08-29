from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLabel, QMessageBox, QHeaderView, QAbstractItemView,
    QSpinBox, QFormLayout, QDialog, QInputDialog, QLineEdit,
)
import time

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QGuiApplication

from core.vault import Vault, Entry, WrongPasswordError

DEFAULT_IDLE_TIMEOUT_SECONDS = 300
DEFAULT_CLIPBOARD_CLEAR_SECONDS = 20


class MainWindow(QWidget):
    def __init__(self, vault: Vault, on_lock):
        """
        on_lock: callback invoked (no args) when the vault locks
        (idle timeout or manual) — the caller (app.py) is responsible
        for tearing this window down and showing the unlock screen again.
        """
        super().__init__()
        self.vault = vault
        self._on_lock = on_lock
        self.idle_timeout = DEFAULT_IDLE_TIMEOUT_SECONDS
        self.clipboard_clear_seconds = DEFAULT_CLIPBOARD_CLEAR_SECONDS
        self._clipboard_secret = None  # tracks what WE put there, to avoid clobbering user copies
        self.sync_settings = {
            "enabled": False,
            "server_url": "http://127.0.0.1:8420",
            "vault_id": "",
            "api_key": "",
            "pinned_sig_pub_b64": None,
            "server_storage_dir": "./sync_storage",
        }

        self.setWindowTitle("PQ Password Vault")
        self.resize(700, 450)
        self._build_ui()
        self._reload_entries()

        # Idle-lock check, polled once a second (spec 5.1: configurable idle timeout)
        self._idle_timer = QTimer(self)
        self._idle_timer.timeout.connect(self._check_idle)
        self._idle_timer.start(1000)

        # Clipboard clear timer, single-shot, (re)armed on each copy
        self._clip_timer = QTimer(self)
        self._clip_timer.setSingleShot(True)
        self._clip_timer.timeout.connect(self._clear_clipboard)

    # ---- UI construction ----

    def _build_ui(self):
        layout = QVBoxLayout()

        toolbar = QHBoxLayout()
        add_btn = QPushButton("+ Add Entry")
        add_btn.clicked.connect(self._add_entry)
        edit_btn = QPushButton("Edit")
        edit_btn.clicked.connect(self._edit_selected)
        delete_btn = QPushButton("Delete")
        delete_btn.clicked.connect(self._delete_selected)
        copy_btn = QPushButton("Copy Password")
        copy_btn.clicked.connect(self._copy_selected_password)
        settings_btn = QPushButton("⚙ Settings")
        settings_btn.clicked.connect(self._open_settings)
        sync_btn = QPushButton("☁ Sync")
        sync_btn.clicked.connect(self._open_sync)
        lock_btn = QPushButton("🔒 Lock Now")
        lock_btn.clicked.connect(self._manual_lock)

        for b in (add_btn, edit_btn, delete_btn, copy_btn):
            toolbar.addWidget(b)
        toolbar.addStretch()
        toolbar.addWidget(settings_btn)
        toolbar.addWidget(sync_btn)
        toolbar.addWidget(lock_btn)
        layout.addLayout(toolbar)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Site", "Username", "Password"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.doubleClicked.connect(self._edit_selected)
        layout.addWidget(self.table)

        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: gray; font-size: 11px;")
        layout.addWidget(self.status_label)

        self.setLayout(layout)

    def _reload_entries(self):
        entries = self.vault.list_entries()
        self.table.setRowCount(len(entries))
        for row, e in enumerate(entries):
            self.table.setItem(row, 0, QTableWidgetItem(e.site))
            self.table.setItem(row, 1, QTableWidgetItem(e.username))
            masked = QTableWidgetItem("•" * min(len(e.password), 12))
            masked.setData(Qt.ItemDataRole.UserRole, e.entry_id)
            self.table.setItem(row, 2, masked)
        self.status_label.setText(f"{len(entries)} entries")

    def _selected_entry_id(self):
        row = self.table.currentRow()
        if row < 0:
            return None
        return self.table.item(row, 2).data(Qt.ItemDataRole.UserRole)

    # ---- CRUD actions ----

    def _add_entry(self):
        from gui.entry_dialog import EntryDialog
        dlg = EntryDialog(self)
        if dlg.exec():
            entry = dlg.get_entry()
            if not entry.site:
                QMessageBox.warning(self, "Missing field", "Site/service is required.")
                return
            self.vault.add_entry(entry)
            self._reload_entries()
        self._touch()

    def _edit_selected(self):
        from gui.entry_dialog import EntryDialog
        entry_id = self._selected_entry_id()
        if entry_id is None:
            return
        current = self.vault.get_entry(entry_id)
        dlg = EntryDialog(self, entry=current)
        if dlg.exec():
            updated = dlg.get_entry()
            self.vault.update_entry(entry_id, updated)
            self._reload_entries()
        self._touch()

    def _delete_selected(self):
        entry_id = self._selected_entry_id()
        if entry_id is None:
            return
        confirm = QMessageBox.question(
            self, "Delete entry", "Delete this entry? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if confirm == QMessageBox.StandardButton.Yes:
            self.vault.delete_entry(entry_id)
            self._reload_entries()
        self._touch()

    def _copy_selected_password(self):
        entry_id = self._selected_entry_id()
        if entry_id is None:
            return
        entry = self.vault.get_entry(entry_id)
        clipboard = QGuiApplication.clipboard()
        clipboard.setText(entry.password)
        self._clipboard_secret = entry.password
        self._clip_timer.start(self.clipboard_clear_seconds * 1000)
        self.status_label.setText(
            f"Password copied — clipboard will clear in {self.clipboard_clear_seconds}s"
        )
        self._touch()

    def _clear_clipboard(self):
        clipboard = QGuiApplication.clipboard()
        # Only clear if it's still our secret — don't clobber something
        # the user copied from elsewhere in the meantime.
        if clipboard.text() == self._clipboard_secret:
            clipboard.setText("")
        self._clipboard_secret = None
        self.status_label.setText(f"{self.table.rowCount()} entries")

    # ---- auto-lock ----

    def _touch(self):
        """Any GUI interaction resets the idle clock, not just vault reads/writes."""
        self.vault.last_activity = time.time()

    def _check_idle(self):
        if self.vault.check_idle_timeout(self.idle_timeout):
            self._do_lock()

    def _manual_lock(self):
        self.vault.lock()
        self._do_lock()

    def _do_lock(self):
        self._idle_timer.stop()
        self._clip_timer.stop()
        self._clear_clipboard()
        self._on_lock()

    # ---- settings ----

    def _open_settings(self):
        dlg = SettingsDialog(self, self.idle_timeout, self.clipboard_clear_seconds)
        if dlg.exec():
            self.idle_timeout = dlg.idle_timeout_spin.value()
            self.clipboard_clear_seconds = dlg.clipboard_spin.value()

    def _open_sync(self):
        from gui.sync_dialog import SyncDialog
        dlg = SyncDialog(self, self.vault, self.sync_settings, on_restore=self._handle_restore)
        dlg.exec()
        self._touch()

    # ---- restoring a downloaded backup ----

    def _handle_restore(self, restore_path: str):
        """
        Called by SyncDialog when the user chooses to switch into a
        just-restored backup immediately, rather than only being told
        its path. The restored file was decrypted under the CURRENTLY
        open vault's key (see core/vault.py restore_backup_blob), so it
        is a snapshot of THIS vault at an earlier point in time, and
        unlocks with the same master password — that password isn't
        retained anywhere in memory between unlocks by design, so it has
        to be asked for again here rather than reused silently.

        The vault currently open in this window is left on disk exactly
        as it is; only the in-memory Vault object backing this window is
        swapped, after the restored file has been confirmed to actually
        unlock.
        """
        password, ok = QInputDialog.getText(
            self, "Unlock Restored Vault",
            "The restored backup uses the same master password as your "
            "current vault. Enter it to open the restored copy:",
            QLineEdit.EchoMode.Password,
        )
        if not ok or not password:
            return

        new_vault = Vault(restore_path)
        try:
            new_vault.unlock(password)
        except WrongPasswordError:
            QMessageBox.critical(
                self, "Wrong password",
                "That password did not unlock the restored backup. Your "
                "currently open vault is unaffected.",
            )
            new_vault.close()
            return
        except Exception as e:
            QMessageBox.critical(
                self, "Restore failed",
                f"Could not open the restored backup: {e}",
            )
            new_vault.close()
            return

        old_db_path = self.vault.storage.db_path
        self.vault.close()
        self.vault = new_vault
        self._reload_entries()
        self.setWindowTitle(f"PQ Password Vault — {restore_path}")
        self._touch()
        QMessageBox.information(
            self, "Switched to restored vault",
            f"This window is now showing the restored backup.\n\n"
            f"Your previous vault file was left unchanged at:\n{old_db_path}",
        )


class SettingsDialog(QDialog):
    def __init__(self, parent, idle_timeout, clipboard_clear_seconds):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        layout = QVBoxLayout()
        form = QFormLayout()

        self.idle_timeout_spin = QSpinBox()
        self.idle_timeout_spin.setRange(30, 3600)
        self.idle_timeout_spin.setSuffix(" s")
        self.idle_timeout_spin.setValue(idle_timeout)
        form.addRow("Auto-lock after idle:", self.idle_timeout_spin)

        self.clipboard_spin = QSpinBox()
        self.clipboard_spin.setRange(5, 300)
        self.clipboard_spin.setSuffix(" s")
        self.clipboard_spin.setValue(clipboard_clear_seconds)
        form.addRow("Clipboard auto-clear after:", self.clipboard_spin)

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