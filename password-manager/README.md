# 🔐 Password Manager

A secure, CLI-based encrypted password vault built in Python. Passwords are stored using AES symmetric encryption via the `cryptography` library's Fernet implementation.

---

## ✨ Features

- 🔐 Master password protected vault
- 💾 Encrypted local storage (AES via Fernet)
- ➕ Add / Update credentials
- 🔍 Retrieve passwords by service name
- 🗑️ Delete entries
- 📋 List all stored services
- 🎲 Generate strong random passwords

---

## 🛠️ Tech Stack

| Library | Purpose |
|---------|---------|
| `cryptography` | Fernet AES encryption |
| `hashlib` | PBKDF2 key derivation |
| `os`, `json` | File-based vault storage |
| `secrets`, `string` | Secure password generation |

---

## 🚀 Usage

### Install dependencies
```bash
pip install cryptography
```

### Run
```bash
python password_manager.py
```

### Menu Options
```
1. Add / Update entry
2. Retrieve entry
3. List all entries
4. Delete entry
5. Generate password
6. Exit
```

---

## 🔒 Security Notes

- The vault key is derived from your master password using **PBKDF2-HMAC-SHA256** with a random salt
- The encrypted vault is stored locally as `vault.enc`
- The salt is stored separately as `salt.key`
- **Never share your master password or vault files**

---

## 📄 License

MIT License