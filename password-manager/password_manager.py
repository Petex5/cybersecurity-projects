#!/usr/bin/env python3
"""
Password Manager
A secure CLI password manager using AES-256 encryption via the cryptography library.
Passwords are stored encrypted in a local JSON vault file.
"""

import os
import sys
import json
import base64
import secrets
import string
import getpass
from pathlib import Path

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    print("[!] Missing dependency. Run: pip install cryptography")
    sys.exit(1)

VAULT_FILE = Path.home() / ".pm_vault.json"
SALT_FILE = Path.home() / ".pm_salt.bin"


def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive an encryption key from the master password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def get_or_create_salt() -> bytes:
    """Load an existing salt or create a new one."""
    if SALT_FILE.exists():
        return SALT_FILE.read_bytes()
    salt = os.urandom(16)
    SALT_FILE.write_bytes(salt)
    return salt


def load_vault(fernet: Fernet) -> dict:
    """Load and decrypt the vault file."""
    if not VAULT_FILE.exists():
        return {}
    try:
        encrypted = VAULT_FILE.read_bytes()
        decrypted = fernet.decrypt(encrypted)
        return json.loads(decrypted)
    except Exception:
        print("[!] Failed to decrypt vault. Wrong master password?")
        sys.exit(1)


def save_vault(vault: dict, fernet: Fernet):
    """Encrypt and save the vault file."""
    data = json.dumps(vault).encode()
    encrypted = fernet.encrypt(data)
    VAULT_FILE.write_bytes(encrypted)


def generate_password(length: int = 16) -> str:
    """Generate a secure random password."""
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))


def print_banner():
    print("=" * 50)
    print("         SECURE PASSWORD MANAGER")
    print("=" * 50)
    print()


def cmd_add(vault: dict, fernet: Fernet):
    site = input("Site/Service name: ").strip()
    username = input("Username/Email  : ").strip()
    choice = input("Generate password? [y/N]: ").strip().lower()
    if choice == 'y':
        try:
            length = int(input("Password length [16]: ").strip() or 16)
        except ValueError:
            length = 16
        password = generate_password(length)
        print(f"[+] Generated password: {password}")
    else:
        password = getpass.getpass("Password        : ")
    vault[site] = {"username": username, "password": password}
    save_vault(vault, fernet)
    print(f"[+] Entry for '{site}' saved.")


def cmd_get(vault: dict):
    if not vault:
        print("[-] Vault is empty.")
        return
    site = input("Site/Service name: ").strip()
    if site in vault:
        entry = vault[site]
        print(f"  Username: {entry['username']}")
        print(f"  Password: {entry['password']}")
    else:
        print(f"[-] No entry found for '{site}'.")


def cmd_list(vault: dict):
    if not vault:
        print("[-] Vault is empty.")
        return
    print(f"\n[+] Stored entries ({len(vault)}):")
    for i, site in enumerate(sorted(vault), 1):
        print(f"  {i}. {site} -> {vault[site]['username']}")
    print()


def cmd_delete(vault: dict, fernet: Fernet):
    site = input("Site/Service name to delete: ").strip()
    if site in vault:
        del vault[site]
        save_vault(vault, fernet)
        print(f"[+] Entry for '{site}' deleted.")
    else:
        print(f"[-] No entry found for '{site}'.")


def cmd_generate():
    try:
        length = int(input("Password length [16]: ").strip() or 16)
    except ValueError:
        length = 16
    pw = generate_password(length)
    print(f"[+] Generated password: {pw}")


def main():
    print_banner()
    master_password = getpass.getpass("Enter master password: ")
    if not master_password:
        print("[!] Master password cannot be empty.")
        sys.exit(1)

    salt = get_or_create_salt()
    key = derive_key(master_password, salt)
    fernet = Fernet(key)
    vault = load_vault(fernet)

    print("[*] Vault unlocked.\n")

    menu = """
Options:
  1. Add / Update entry
  2. Retrieve entry
  3. List all entries
  4. Delete entry
  5. Generate password
  6. Exit
"""

    while True:
        print(menu)
        choice = input("Select option [1-6]: ").strip()
        print()
        if choice == '1':
            cmd_add(vault, fernet)
        elif choice == '2':
            cmd_get(vault)
        elif choice == '3':
            cmd_list(vault)
        elif choice == '4':
            cmd_delete(vault, fernet)
        elif choice == '5':
            cmd_generate()
        elif choice == '6':
            print("[*] Goodbye!")
            sys.exit(0)
        else:
            print("[!] Invalid option. Please enter 1-6.")


if __name__ == "__main__":
    main()