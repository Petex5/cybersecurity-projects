#!/usr/bin/env python3
"""
Network Sniffer — Educational Python Tool
===============================================================================
A basic packet capture utility for analysing network traffic. Designed for
educational and authorised security testing purposes only.

Features:
- Raw packet capture using Python sockets
- Packet header parsing (Ethernet, IP, TCP/UDP/ICMP)
- Protocol identification and statistics tracking
- Real-time packet summary display
- Filter by IP address or protocol
- Session summary report on exit
"""

import socket
import struct
import sys
import signal
import argparse
from collections import defaultdict


# =============================================================================
# GLOBAL STATISTICS
# =============================================================================

packet_count = 0
protocol_stats = defaultdict(int)
source_ip_stats = defaultdict(int)
dest_ip_stats = defaultdict(int)
ip_version_stats = defaultdict(int)
running = True


# =============================================================================
# SIGNAL HANDLER
# =============================================================================

def signal_handler(sig, frame):
    """Gracefully stop capture and print summary."""
    global running
    running = False
    print("\n\n" + "=" * 80)
    print(" CAPTURE STOPPED — SESSION SUMMARY")
    print("=" * 80)
    print(f"\nTotal packets captured: {packet_count}")
    print()
    if protocol_stats:
        print("Protocol Distribution:")
        for proto, count in sorted(protocol_stats.items(), key=lambda x: x[1], reverse=True):
            print(f"  {proto}: {count}")
    if source_ip_stats:
        print("\nTop Source IPs:")
        for ip, count in sorted(source_ip_stats.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {ip}: {count}")
    if dest_ip_stats:
        print("\nTop Destination IPs:")
        for ip, count in sorted(dest_ip_stats.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {ip}: {count}")
    print("\n" + "=" * 80)
    sys.exit(0)


# =============================================================================
# PACKET PARSING FUNCTIONS
# =============================================================================

def parse_ethernet_header(raw_data):
    """Parse Ethernet header — returns destination/source MAC, eth protocol."""
    dest_mac = ":".join(f"{x:02x}" for x in raw_data[:6])
    source_mac = ":".join(f"{x:02x}" for x in raw_data[6:12])
    eth_protocol = struct.unpack("!H", raw_data[12:14])[0]
    return dest_mac, source_mac, eth_protocol


def parse_ip_header(raw_data):
    """Parse IPv4 header — returns source/dest IP, protocol, TTL, header length."""
    version = (raw_data[0] >> 4) & 0x0F
    header_length = (raw_data[0] & 0x0F) * 4
    total_length = struct.unpack("!H", raw_data[2:4])[0]
    ttl = raw_data[8]
    protocol = raw_data[9]
    source_ip = socket.inet_ntoa(raw_data[12:16])
    dest_ip = socket.inet_ntoa(raw_data[16:20])
    return {
        "version": 4,
        "header_len": header_length,
        "total_len": total_length,
        "ttl": ttl,
        "protocol": protocol,
        "src_ip": source_ip,
        "dst_ip": dest_ip,
    }


def parse_tcp_header(raw_data):
    """Parse TCP header — returns source/dest port, seq, ack, flags."""
    source_port = struct.unpack("!H", raw_data[:2])[0]
    dest_port = struct.unpack("!H", raw_data[2:4])[0]
    seq_num = struct.unpack("!I", raw_data[4:8])[0]
    ack_num = struct.unpack("!I", raw_data[8:12])[0]
    offset = (raw_data[12] >> 4) * 4
    flags = raw_data[13]
    flag_str = ""
    if flags & 0x01:
        flag_str += "FIN "
    if flags & 0x02:
        flag_str += "SYN "
    if flags & 0x04:
        flag_str += "RST "
    if flags & 0x08:
        flag_str += "PSH "
    if flags & 0x10:
        flag_str += "ACK "
    if flags & 0x20:
        flag_str += "URG "
    return {
        "src_port": source_port,
        "dst_port": dest_port,
        "seq_num": seq_num,
        "ack_num": ack_num,
        "flags": flag_str.strip(),
        "header_len": offset,
    }


def parse_udp_header(raw_data):
    """Parse UDP header — returns source/dest port, length."""
    source_port = struct.unpack("!H", raw_data[:2])[0]
    dest_port = struct.unpack("!H", raw_data[2:4])[0]
    pkt_len = struct.unpack("!H", raw_data[4:6])[0]
    return {
        "src_port": source_port,
        "dst_port": dest_port,
        "length": pkt_len,
    }


def parse_icmp_header(raw_data):
    """Parse ICMP header — returns type and code."""
    pkt_type = raw_data[0]
    code = raw_data[1]
    checksum = struct.unpack("!H", raw_data[2:4])[0]
    return {"type": pkt_type, "code": code, "checksum": checksum}


def get_protocol_name(eth_proto):
    """Map Ethernet protocol number to name."""
    names = {
        0x0800: "IPv4",
        0x0806: "ARP",
        0x86DD: "IPv6",
        0x8100: "VLAN",
    }
    return names.get(eth_proto, "Unknown")


def get_ip_protocol_name(ip_proto):
    """Map IP protocol number to name."""
    names = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        47: "GRE",
        50: "ESP",
        51: "AH",
    }
    return names.get(ip_proto, "Other")


# =============================================================================
# PACKET HANDLER
# =============================================================================

def handle_packet(raw_data, src_ip_filter, protocol_filter):
    """Parse and display packet information."""
    global packet_count

    packet_count += 1

    # Parse Ethernet header
    dest_mac, source_mac, eth_proto = parse_ethernet_header(raw_data)
    eth_name = get_protocol_name(eth_proto)

    if src_ip_filter or protocol_filter:
        if eth_proto != 0x0800:
            return

        ip_header = parse_ip_header(raw_data[14:])
        src_ip = ip_header["src_ip"]
        dst_ip = ip_header["dst_ip"]
        ip_proto = ip_header["protocol"]
        ip_name = get_ip_protocol_name(ip_proto)

        if src_ip_filter and src_ip != src_ip_filter:
            return
        if protocol_filter and ip_name.upper() != protocol_filter.upper():
            return

        print(f"\n[{eth_name}] {ip_name or 'Other'}  {src_ip} -> {dst_ip}")
        print(f"  Ports: check below")
        if ip_proto == 6:
            tcp = parse_tcp_header(raw_data[14 + ip_header["header_len"]:])
            print(f"  TCP: {tcp['src_port']} -> {tcp['dst_port']} | Flags: {tcp['flags']}")
        elif ip_proto == 17:
            udp = parse_udp_header(raw_data[14 + ip_header["header_len"]:])
            print(f"  UDP: {udp['src_port']} -> {udp['dst_port']} | Len: {udp['length']}")
        elif ip_proto == 1:
            icmp = parse_icmp_header(raw_data[14 + ip_header["header_len"]:])
            print(f"  ICMP: Type={icmp['type']} Code={icmp['code']}")

        protocol_stats[ip_name] += 1
        source_ip_stats[src_ip] += 1
        dest_ip_stats[dst_ip] += 1

    else:
        # No filter — show all packets summary
        print(f"\n[{eth_name}] MAC: {source_mac[:8]}... -> {dest_mac[:8]}...")
        if eth_proto == 0x0800:
            ip_header = parse_ip_header(raw_data[14:])
            protocol_stats["IPv4"] += 1
            source_ip_stats[ip_header["src_ip"]] += 1
            dest_ip_stats[ip_header["dst_ip"]] += 1
            ip_name = get_ip_protocol_name(ip_header["protocol"])
            print(f"  IPv4: {ip_header['src_ip']} -> {ip_header['dst_ip']} | {ip_name} | TTL={ip_header['ttl']}")
            if ip_header["protocol"] == 6:
                tcp = parse_tcp_header(raw_data[14 + ip_header["header_len"]:])
                print(f"  TCP: {tcp['src_port']} -> {tcp['dst_port']} | {tcp['flags']}")
            elif ip_header["protocol"] == 17:
                udp = parse_udp_header(raw_data[14 + ip_header["header_len"]:])
                print(f"  UDP: {udp['src_port']} -> {udp['dst_port']}")
        elif eth_proto == 0x0806:
            protocol_stats["ARP"] += 1
            print("  ARP packet detected")


# =============================================================================
# PROMISCIOUS MODE SETUP
# =============================================================================

def set_promiscuous_mode(socket_obj, interface):
    """Set network interface to promiscuous mode (Linux)."""
    try:
        import fcntl
        import struct
        SIOCGIFFLAGS = 0x8913
        SIOCSIFFLAGS = 0x8914
        IFF_PROMISC = 0x100
        ifreq = struct.pack("16sH", interface.encode("utf-8"), 0)
        flags = struct.unpack("16sH", fcntl.ioctl(socket_obj, SIOCGIFFLAGS, ifreq))[1]
        flags |= IFF_PROMISC
        ifreq = struct.pack("16sH", interface.encode("utf-8"), flags)
        fcntl.ioctl(socket_obj, SIOCSIFFLAGS, ifreq)
        print(f"Interface {interface} set to promiscuous mode")
    except PermissionError:
        print("Warning: Permission denied. Run with sudo for full capture.")
    except ImportError:
        pass


# =============================================================================
# MAIN FUNCTION
# =============================================================================

def main():
    global running
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    parser = argparse.ArgumentParser(
        description="Network Sniffer — Capture and analyse network packets"
    )
    parser.add_argument(
        "-i",
        "--interface",
        default="eth0",
        help="Network interface (e.g., eth0)">
Default: eth0",
    )
    parser.add_argument(
        "-f",
        "--filter-ip",
        help="Filter packets by source IP address",
    )
    parser.add_argument(
        "-p",
        "--filter-proto",
        choices=["TCP", "UDP", "ICMP", "ARP", "IPv4", "IPv6"],
        help="Filter packets by protocol (TCP, UDP, ICMP, ARP, IPv4, IPv6)",
    )

    args = parser.parse_args()

    print("=" * 80)
    print(" NETWORK SNIFFER — Educational Packet Capt

ure Utility")
    print("=" * 80)
    print("AUTH & ETHICAL NOTICE")
    print("- This tool captures network packets on the local interface.")
    print("- It is intended for educational and authorised security testing.")
    print("- Capture unauthorised traffic may violate laws and policies.")
    print("- Use only on networks you own or have written permission to test.")
    print("=" * 80)
    print()
    print(f"Interface: {args.interface}")
    if args.filter_ip:
        print(f"Source IP filter: {args.filter_ip}")
    if args.filter_proto:
        print(f"Protocol filter: {args.filter_proto}")
    print()
    print("Press Ctrl+C to stop capture and view session summary...")
    print("-" * 80)

    try:
        raw_socket = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.ntohs(3),
        )
        set_promiscuous_mode(raw_socket, args.interface)
    except PermissionError:
        print("Error: Permission denied. Please run with sudo privileges.")
        print("Example: sudo python3 network_sniffer.py -i eth0")
        sys.exit(1)
    except Exception as e:
        print(f"Error creating socket: {e}")
        sys.exit(1)

    while running:
        try:
            raw_data, addr = raw_socket.recvfrom(65536)
            handle_packet(
                raw_data,
                src_ip_filter=args.filter_ip,
                protocol_filter=args.filter_proto,
            )
        except Exception:
            if running:
                pass

    raw_socket.close()


if __name__ == "__main__":

    main()
