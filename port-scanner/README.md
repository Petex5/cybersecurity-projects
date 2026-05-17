# 🛡️ Port Scanner

A fast, multi-threaded TCP port scanner written in Python. Identifies open ports on a target host, maps them to known services, and optionally grabs banners for fingerprinting.

---

## 🚀 Features

- **Multi-threaded scanning** — configurable thread count for speed
- **Service detection** — maps open ports to common service names
- **Banner grabbing** — optional banner retrieval for fingerprinting
- **Flexible port ranges** — single ports, ranges, or comma-separated lists
- **Clean output** — formatted scan summary with timing

---

## 🔧 Requirements

- Python 3.8+
- No third-party libraries required (uses standard library only)

---

## 🚀 Usage

```bash
python port_scanner.py <target> [options]
```

### Arguments

| Argument | Description |
|---|---|
| `target` | Hostname or IP address to scan |
| `-p`, `--ports` | Port range (e.g. `80`, `1-1024`, `22,80,443`) |
| `--common` | Scan common well-known ports only |
| `-t`, `--threads` | Number of threads (default: 100) |
| `--timeout` | Connection timeout in seconds (default: 1.0) |
| `--banner` | Attempt banner grabbing on open ports |

### Examples

```bash
# Scan default ports 1-1024
python port_scanner.py 192.168.1.1

# Scan a specific range
python port_scanner.py example.com -p 1-65535

# Scan specific ports with banner grabbing
python port_scanner.py 10.0.0.1 -p 22,80,443 --banner

# Scan common ports with more threads
python port_scanner.py target.com --common -t 200 --timeout 0.5
```

---

### 📋 Sample Output

```
============================================================
  Port Scanner
============================================================
  Target     : example.com
  IP Address : 93.184.216.34
  Ports      : 1024 port(s)
  Threads    : 100
  Timeout    : 1.0s
  Started    : 2026-05-17 19:00:00
============================================================

  [OPEN]  Port    22  SSH
  [OPEN]  Port    80  HTTP
  [OPEN]  Port   443  HTTPS

============================================================
  Scan complete in 3.42s
  Open ports found: 3

  Summary:
    Port     22  SSH
    Port     80  HTTP
    Port    443  HTTPS
============================================================
```

---

## ⚠️ Legal & Ethical Notice

> Only scan hosts you **own** or have **explicit written permission** to scan.
> Unauthorised port scanning may be illegal under the Computer Misuse Act 1990 (UK) and equivalent laws in other jurisdictions.
> This tool is intended for **educational and authorised security testing** purposes only.

---

## 📄 License

MIT License
