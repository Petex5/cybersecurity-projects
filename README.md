# 🛡️ Cybersecurity Projects

A collection of Python-based cybersecurity tools built for learning, demonstration, and portfolio purposes. Each tool is self-contained and designed with clean code practices.

---

## 📁 Repository Structure

```
cybersecurity-projects/
├── hash-identifier/
│   ├── hash_identifier.py
│   └── README.md
├── http-headers-scanner/
│   ├── http_headers_scanner.py
│   └── README.md
├── password-manager/
│   ├── password_manager.py
│   └── README.md
└── README.md
```

---

## 🔧 Projects

### 1. 🔍 Hash Identifier
Identifies cryptographic hash types (MD5, SHA-1, SHA-256, etc.) from a given hash string using pattern matching.

**Skills demonstrated:** Regex, pattern matching, cryptography fundamentals

→ [View Project](./hash-identifier/README.md)

---

### 2. 🌐 HTTP Headers Scanner
Scans a target URL and analyses HTTP response headers for common security misconfigurations and missing security headers.

**Skills demonstrated:** HTTP requests, security header analysis, web security

→ [View Project](./http-headers-scanner/README.md)

---

### 3. 🔐 Password Manager
A CLI-based encrypted password vault using AES encryption (via Fernet) to securely store, retrieve, and manage credentials.

**Skills demonstrated:** Symmetric encryption, key derivation, secure storage, CLI design

→ [View Project](./password-manager/README.md)

---

## 🚀 Getting Started

### Prerequisites
- Python 3.8+
- pip

### Installation
```bash
git clone https://github.com/Petex5/cybersecurity-projects.git
cd cybersecurity-projects
```

Each project has its own dependencies listed in its README.

---

## 🧰 Tech Stack

| Tool | Purpose |
|------|---------|
| Python 3 | Core language |
| `requests` | HTTP scanning |
| `cryptography` | Fernet encryption |
| `hashlib` | Hash operations |
| `argparse` | CLI interfaces |

---

## 👤 Author

Built as part of a cybersecurity portfolio to demonstrate practical Python scripting and security tooling skills.

- GitHub: [@Petex5](https://github.com/Petex5)

---

## 📄 License

MIT License — free to use and modify.