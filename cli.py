#!/usr/bin/env python3
"""
Minimal CLI for the offline core vault (Week 1 deliverable).

This is a scaffold to exercise and demo the core module before the
PyQt6 GUI lands in Week 2. Run: python3 cli.py <path-to-vault-file>
"""

import getpass
import os
import sys

from core.vault import (
    Vault, Entry, WeakPasswordError, WrongPasswordError,
    VaultLockedError,
)
from core.clipboard import copy_with_autoclear

IDLE_TIMEOUT_SECONDS = 300
CLIPBOARD_CLEAR_SECONDS = 20


def prompt_master_password(confirm: bool = False) -> str:
    pw = getpass.getpass("Master password: ")
    if confirm:
        pw2 = getpass.getpass("Confirm master password: ")
        if pw != pw2:
            print("Passwords did not match.")
            sys.exit(1)
    return pw


def open_or_create_vault(db_path: str) -> Vault:
    vault = Vault(db_path)
    if vault.storage.is_initialized():
        pw = prompt_master_password()
        try:
            vault.unlock(pw)
        except WrongPasswordError as e:
            print(f"Error: {e}")
            sys.exit(1)
        print("Vault unlocked.")
    else:
        print(f"No vault found at {db_path} — creating a new one.")
        print("Master password policy: 12+ chars, must not be easily guessable (zxcvbn score >= 3).")
        pw = prompt_master_password(confirm=True)
        try:
            vault.create(pw)
        except WeakPasswordError as e:
            print(f"Error: {e}")
            sys.exit(1)
        print("Vault created and unlocked.")
    return vault


def print_help():
    print("""
Commands:
  add                 add a new entry
  list                list all entries (masked passwords)
  show <id>           show one entry, offer to copy password to clipboard
  update <id>         update an entry
  delete <id>         delete an entry
  lock                lock the vault (must re-enter master password to continue)
  help                show this message
  quit                exit
""")


def cmd_add(vault: Vault):
    site = input("Site/service: ").strip()
    username = input("Username: ").strip()
    password = getpass.getpass("Password (input hidden): ")
    notes = input("Notes (optional): ").strip()
    entry_id = vault.add_entry(Entry(site=site, username=username, password=password, notes=notes))
    print(f"Added entry #{entry_id}.")


def cmd_list(vault: Vault):
    entries = vault.list_entries()
    if not entries:
        print("(vault is empty)")
        return
    print(f"{'ID':<4} {'Site':<25} {'Username':<25} Password")
    for e in entries:
        masked = "*" * min(len(e.password), 12)
        print(f"{e.entry_id:<4} {e.site:<25} {e.username:<25} {masked}")


def cmd_show(vault: Vault, entry_id: int):
    try:
        e = vault.get_entry(entry_id)
    except KeyError:
        print("No such entry.")
        return
    print(f"Site:     {e.site}")
    print(f"Username: {e.username}")
    print(f"Notes:    {e.notes or '(none)'}")
    choice = input("Copy password to clipboard? [y/N]: ").strip().lower()
    if choice == "y":
        ok = copy_with_autoclear(e.password, CLIPBOARD_CLEAR_SECONDS)
        if ok:
            print(f"Copied. Clipboard will auto-clear in {CLIPBOARD_CLEAR_SECONDS}s.")
        else:
            print("No system clipboard available in this environment — "
                  f"password: {e.password}  (would normally NOT be printed; "
                  "GUI version in Week 2 uses QClipboard instead)")


def cmd_update(vault: Vault, entry_id: int):
    try:
        existing = vault.get_entry(entry_id)
    except KeyError:
        print("No such entry.")
        return
    print("Leave blank to keep current value.")
    site = input(f"Site [{existing.site}]: ").strip() or existing.site
    username = input(f"Username [{existing.username}]: ").strip() or existing.username
    password = getpass.getpass("New password (blank = keep current): ") or existing.password
    notes = input(f"Notes [{existing.notes}]: ").strip() or existing.notes
    vault.update_entry(entry_id, Entry(site=site, username=username, password=password, notes=notes))
    print("Updated.")


def cmd_delete(vault: Vault, entry_id: int):
    confirm = input(f"Delete entry #{entry_id}? [y/N]: ").strip().lower()
    if confirm == "y":
        try:
            vault.delete_entry(entry_id)
            print("Deleted.")
        except KeyError:
            print("No such entry.")


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 cli.py <path-to-vault-file>")
        sys.exit(1)

    db_path = sys.argv[1]
    vault = open_or_create_vault(db_path)
    print_help()

    try:
        while True:
            if vault.check_idle_timeout(IDLE_TIMEOUT_SECONDS):
                print(f"\n[Auto-locked after {IDLE_TIMEOUT_SECONDS}s idle. Re-enter master password.]")
                pw = prompt_master_password()
                try:
                    vault.unlock(pw)
                except WrongPasswordError as e:
                    print(f"Error: {e}")
                    continue

            try:
                raw = input("\nvault> ").strip()
            except EOFError:
                break
            if not raw:
                continue
            parts = raw.split()
            cmd, args = parts[0], parts[1:]

            try:
                if cmd == "add":
                    cmd_add(vault)
                elif cmd == "list":
                    cmd_list(vault)
                elif cmd == "show" and args:
                    cmd_show(vault, int(args[0]))
                elif cmd == "update" and args:
                    cmd_update(vault, int(args[0]))
                elif cmd == "delete" and args:
                    cmd_delete(vault, int(args[0]))
                elif cmd == "lock":
                    vault.lock()
                    print("Vault locked.")
                    pw = prompt_master_password()
                    try:
                        vault.unlock(pw)
                    except WrongPasswordError as e:
                        print(f"Error: {e}")
                elif cmd == "help":
                    print_help()
                elif cmd in ("quit", "exit"):
                    break
                else:
                    print("Unknown command. Type 'help'.")
            except VaultLockedError:
                print("Vault is locked. Restart the CLI to unlock.")
    finally:
        vault.close()
        print("\nVault closed, key wiped from memory. Bye.")


if __name__ == "__main__":
    main()
