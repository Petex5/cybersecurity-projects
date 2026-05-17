# HTTP Headers Security Scanner

A Python command-line tool that fetches and analyses HTTP response headers from any target URL, identifying security misconfigurations and information disclosure risks.

## Features

- Fetches all HTTP response headers from a target URL
- Identifies missing critical security headers
- Flags information disclosure headers (e.g., `Server`, `X-Powered-By`)
- Calculates a security score based on header presence
- Supports both CLI argument and interactive input
- Follows redirects automatically

## Requirements

- Python 3.6+
- `requests` library

```bash
pip install requests
```

## Usage

```bash
# Interactive mode
python http_headers_scanner.py

# Pass URL as argument
python http_headers_scanner.py https://example.com
```

## Security Headers Checked

| Header | Purpose |
|--------|---------|
| `Strict-Transport-Security` | Enforces HTTPS connections |
| `Content-Security-Policy` | Prevents XSS and injection attacks |
| `X-Content-Type-Options` | Prevents MIME-type sniffing |
| `X-Frame-Options` | Prevents clickjacking |
| `X-XSS-Protection` | Legacy XSS filter |
| `Referrer-Policy` | Controls referrer information |
| `Permissions-Policy` | Restricts browser feature access |
| `Cache-Control` | Controls caching behaviour |

## Example Output

```
============================================================
         HTTP HEADERS SECURITY SCANNER
============================================================

[*] Scanning: https://example.com

[+] SECURITY HEADERS PRESENT:
--------------------------------------------------
  [OK]  Strict-Transport-Security: max-age=31536000
  [OK]  X-Content-Type-Options: nosniff

[-] MISSING SECURITY HEADERS:
--------------------------------------------------
  [!!] Content-Security-Policy
  [!!] X-Frame-Options

[!] INFORMATION DISCLOSURE RISK:
--------------------------------------------------
  [WARN] Server: Apache/2.4.41

[*] Security Score: 25.0% (2/8 headers present)
============================================================
```

## Author

Built as part of a cybersecurity portfolio project.