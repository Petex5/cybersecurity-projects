#!/usr/bin/env python3
"""
HTTP Headers Scanner
A cybersecurity tool to analyse HTTP response headers for security misconfigurations.
"""

import sys
import requests
from urllib.parse import urlparse

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cache-Control",
]

INFORMATION_DISCLOSURE = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


def print_banner():
    print("=" * 60)
    print("         HTTP HEADERS SECURITY SCANNER")
    print("=" * 60)
    print()


def validate_url(url):
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
    return url


def fetch_headers(url):
    try:
        response = requests.get(url, timeout=10, allow_redirects=True,
                                headers={"User-Agent": "SecurityScanner/1.0"})
        return response.headers, response.status_code, response.url
    except requests.exceptions.ConnectionError:
        print(f"[!] Connection error: Unable to reach {url}")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print(f"[!] Timeout: {url} did not respond in time.")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"[!] Request error: {e}")
        sys.exit(1)


def analyse_headers(headers):
    present = []
    missing = []
    info_disclosure = []

    for header in SECURITY_HEADERS:
        if header in headers:
            present.append((header, headers[header]))
        else:
            missing.append(header)

    for header in INFORMATION_DISCLOSURE:
        if header in headers:
            info_disclosure.append((header, headers[header]))

    return present, missing, info_disclosure


def print_results(url, status_code, final_url, headers, present, missing, info_disclosure):
    print(f"[*] Target     : {url}")
    print(f"[*] Final URL  : {final_url}")
    print(f"[*] Status Code: {status_code}")
    print()

    print("[+] ALL RESPONSE HEADERS:")
    print("-" * 50)
    for key, value in headers.items():
        print(f"  {key}: {value}")
    print()

    print("[+] SECURITY HEADERS PRESENT:")
    print("-" * 50)
    if present:
        for header, value in present:
            print(f"  [OK]  {header}: {value}")
    else:
        print("  None found.")
    print()

    print("[-] MISSING SECURITY HEADERS:")
    print("-" * 50)
    if missing:
        for header in missing:
            print(f"  [!!] {header}")
    else:
        print("  All checked security headers are present.")
    print()

    if info_disclosure:
        print("[!] INFORMATION DISCLOSURE RISK:")
        print("-" * 50)
        for header, value in info_disclosure:
            print(f"  [WARN] {header}: {value}")
        print()

    score = len(present) / len(SECURITY_HEADERS) * 100
    print(f"[*] Security Score: {score:.1f}% ({len(present)}/{len(SECURITY_HEADERS)} headers present)")
    print("=" * 60)


def main():
    print_banner()

    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = input("Enter the target URL: ").strip()
        if not url:
            print("[!] No URL provided.")
            sys.exit(1)

    url = validate_url(url)
    print(f"\n[*] Scanning: {url}\n")

    headers, status_code, final_url = fetch_headers(url)
    present, missing, info_disclosure = analyse_headers(headers)
    print_results(url, status_code, final_url, headers, present, missing, info_disclosure)


if __name__ == "__main__":
    main()