"""
Command-line helper for registering or revoking a vault's access on a
sync server, so the operator can hand the printed API key to the client
out-of-band — the same kind of operational step as copying an SSH
public key to a server's authorized_keys, just in the other direction
(here the SERVER hands the CLIENT a secret, rather than the reverse).

Usage:
    python -m sync.manage_access register <vault_id> [--storage-dir DIR] [--overwrite]
    python -m sync.manage_access revoke   <vault_id> [--storage-dir DIR]

The storage dir must match PQVAULT_SYNC_STORAGE (or --storage-dir) used
by the running server, since the access store file lives alongside the
blob store and signing key inside it.
"""

import argparse
import os

from sync.access_store import VaultAccessStore


def main():
    parser = argparse.ArgumentParser(description="Manage sync server vault access.")
    parser.add_argument("action", choices=["register", "revoke"])
    parser.add_argument("vault_id")
    parser.add_argument(
        "--storage-dir",
        default=os.environ.get("PQVAULT_SYNC_STORAGE", "./sync_storage"),
        help="Must match the running server's storage directory.",
    )
    parser.add_argument(
        "--overwrite", action="store_true",
        help="Rotate the key if vault_id is already registered (invalidates the old key immediately).",
    )
    args = parser.parse_args()

    os.makedirs(args.storage_dir, exist_ok=True)
    store = VaultAccessStore(os.path.join(args.storage_dir, "vault_access.json"))

    if args.action == "register":
        key = store.register(args.vault_id, overwrite=args.overwrite)
        print(f"Registered {args.vault_id!r}.")
        print("API key (copy this into the client's SyncClient(api_key=...) config — it will not be shown again):")
        print(key)
    else:
        removed = store.revoke(args.vault_id)
        if removed:
            print(f"Revoked access for {args.vault_id!r}.")
        else:
            print(f"No existing registration found for {args.vault_id!r} — nothing to revoke.")


if __name__ == "__main__":
    main()