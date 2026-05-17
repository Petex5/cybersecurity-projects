# Network Sniffer

A Python-based raw socket network sniffer that captures and analyzes TCP, UDP, and ICMP packets on the network interface. Designed for educational and network diagnostic purposes.

## Description

This tool provides a lightweight, opt-in network sniffing utility using Python's raw socket capabilities. It enables users to monitor network traffic in real-time, displaying packet information including protocol type, source/destination IP addresses, and parsed payload data for supported protocols.

## Usage

```bash
python network_sniffer.py
```

### How It Works

1. Creates a raw socket bound to the primary network interface
2. Promiscuous mode captures all packets regardless of destination
3. Parses IP headers to extract protocol information
4. Identifies TCP, UDP, and ICMP protocols and displays relevant fields
5. Continuously monitors traffic until interrupted (Ctrl+C)

## Requirements

- Python 3.6+
- Root/Administrator privileges (required for raw socket operations)
- Compatible with Linux and Windows operating systems

## Installation

No external dependencies are required. Simply clone the repository and run:

```bash
sudo python network_sniffer.py  # Linux/macOS
python network_sniffer.py       # Windows (as Administrator)
```

## Legal Disclaimer

This tool is intended for **educational purposes**, **authorized security testing**, and **network diagnostics** only. Always obtain proper authorization before capturing or analyzing network traffic. Unauthorized packet capture may violate laws and regulations in your jurisdiction.

## License

This project is licensed under the MIT License.

## Attribution

Part of the **Cybersecurity Projects** collection by Petex5.
