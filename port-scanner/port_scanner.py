#!/usr/bin/env python3
"""
Port Scanner - A multi-threaded TCP port scanner with service detection and banner grabbing.

Features:
    - Multi-threaded scanning for fast results
    - Service name detection for common ports
    - Optional banner grabbing
    - Flexible port range specification
    - Clean summary output

Usage:
    python port_scanner.py <target> [options]

Author: Cybersecurity Portfolio Project
License: MIT
"""

import socket
import threading
import argparse
import sys
from queue import Queue
from datetime import datetime

# Common services mapping
COMMON_SERVICES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis',
    8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB'
}

open_ports = []
lock = threading.Lock()


def resolve_host(host):
    """Resolve hostname to IP address."""
    try:
        ip = socket.gethostbyname(host)
        return ip
    except socket.gaierror:
        print(f'[!] Cannot resolve hostname: {host}')
        sys.exit(1)


def grab_banner(ip, port, timeout):
    """Attempt to grab service banner."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.send(b'HEAD / HTTP/1.0\r\n\r\n')
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        return banner.split('\n')[0] if banner else None
    except Exception:
        return None


def scan_port(ip, port, timeout, banner):
    """Scan a single TCP port."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        if result == 0:
            service = COMMON_SERVICES.get(port, 'Unknown')
            banner_info = None
            if banner:
                banner_info = grab_banner(ip, port, timeout)
            with lock:
                open_ports.append((port, service, banner_info))
                print(f'  [OPEN]  Port {port:5d}  {service}')
                if banner_info:
                    print(f'          Banner: {banner_info[:60]}')
    except Exception:
        pass


def worker(ip, timeout, banner, queue):
    """Thread worker function."""
    while not queue.empty():
        port = queue.get()
        scan_port(ip, port, timeout, banner)
        queue.task_done()


def parse_ports(port_str):
    """Parse port string into list of port numbers."""
    ports = []
    for part in port_str.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-')
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def print_banner(host, ip, ports, threads, timeout):
    """Print scan header."""
    print('=' * 60)
    print('  Port Scanner')
    print('=' * 60)
    print(f'  Target     : {host}')
    print(f'  IP Address : {ip}')
    print(f'  Ports      : {len(ports)} port(s)')
    print(f'  Threads    : {threads}')
    print(f'  Timeout    : {timeout}s')
    print(f'  Started    : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    print('=' * 60)
    print()


def print_summary(start_time):
    """Print scan summary."""
    elapsed = (datetime.now() - start_time).total_seconds()
    print()
    print('=' * 60)
    print(f'  Scan complete in {elapsed:.2f}s')
    print(f'  Open ports found: {len(open_ports)}')
    if open_ports:
        print()
        print('  Summary:')
        for port, service, _ in sorted(open_ports):
            print(f'    Port  {port:5d}  {service}')
    print('=' * 60)


def main():
    parser = argparse.ArgumentParser(
        description='Multi-threaded TCP Port Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python port_scanner.py 192.168.1.1
  python port_scanner.py example.com -p 1-1024
  python port_scanner.py 10.0.0.1 -p 22,80,443 --banner
  python port_scanner.py target.com --common -t 200
        """
    )
    parser.add_argument('target', help='Target hostname or IP address')
    parser.add_argument('-p', '--ports', default='1-1024',
                        help='Ports to scan (e.g. 80, 1-1024, 22,80,443) [default: 1-1024]')
    parser.add_argument('--common', action='store_true',
                        help='Scan common well-known ports only')
    parser.add_argument('-t', '--threads', type=int, default=100,
                        help='Number of threads [default: 100]')
    parser.add_argument('--timeout', type=float, default=1.0,
                        help='Connection timeout in seconds [default: 1.0]')
    parser.add_argument('--banner', action='store_true',
                        help='Attempt banner grabbing on open ports')

    args = parser.parse_args()

    host = args.target
    ip = resolve_host(host)

    if args.common:
        ports = sorted(COMMON_SERVICES.keys())
    else:
        try:
            ports = parse_ports(args.ports)
        except ValueError:
            print('[!] Invalid port specification.')
            sys.exit(1)

    start_time = datetime.now()
    print_banner(host, ip, ports, args.threads, args.timeout)

    queue = Queue()
    for port in ports:
        queue.put(port)

    threads = []
    for _ in range(min(args.threads, len(ports))):
        t = threading.Thread(
            target=worker,
            args=(ip, args.timeout, args.banner, queue)
        )
        t.daemon = True
        t.start()
        threads.append(t)

    queue.join()
    print_summary(start_time)


if __name__ == '__main__':
    main()
