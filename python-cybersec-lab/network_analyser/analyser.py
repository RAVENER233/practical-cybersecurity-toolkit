
import argparse
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR

BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports"

protocol_counts = Counter()
source_counts = Counter()
destination_counts = Counter()
captured_packets = []


def analyse_packet(packet):
    if not packet.haslayer(IP):
        return

    ip = packet[IP]

    if packet.haslayer(TCP):
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif packet.haslayer(UDP):
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    elif packet.haslayer(ICMP):
        protocol = "ICMP"
        source_port = None
        destination_port = None

    else:
        protocol = "OTHER"
        source_port = None
        destination_port = None

    dns_query = None

    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        try:
            dns_query = packet[DNSQR].qname.decode(
                "utf-8", errors="replace"
            ).rstrip(".")
        except (AttributeError, UnicodeDecodeError):
            dns_query = None

    packet_info = {
        "time": datetime.now().isoformat(),
        "source_ip": ip.src,
        "destination_ip": ip.dst,
        "protocol": protocol,
        "source_port": source_port,
        "destination_port": destination_port,
        "packet_size": len(packet),
        "dns_query": dns_query
    }

    captured_packets.append(packet_info)

    protocol_counts[protocol] += 1
    source_counts[ip.src] += 1
    destination_counts[ip.dst] += 1

    print(
        f"[{protocol}] {ip.src} -> {ip.dst} "
        f"| Size: {len(packet)} bytes"
    )


def save_report():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    report = {
        "capture_time": datetime.now().isoformat(),
        "total_packets": len(captured_packets),
        "protocol_counts": dict(protocol_counts),
        "top_source_ips": dict(source_counts.most_common(10)),
        "top_destination_ips": dict(
            destination_counts.most_common(10)
        ),
        "packets": captured_packets
    }

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = REPORT_DIR / f"network_report_{timestamp}.json"

    report_file.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8"
    )

    print("\nNETWORK ANALYSIS SUMMARY")
    print("=" * 40)
    print(f"Total packets: {len(captured_packets)}")
    print(f"Protocols: {dict(protocol_counts)}")
    print(f"Top source IPs: {dict(source_counts.most_common(5))}")
    print("=" * 40)
    print(f"Report saved: {report_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Python Network Traffic Analyser"
    )

    parser.add_argument(
        "-i", "--interface",
        help="Network interface to monitor"
    )

    parser.add_argument(
        "-c", "--count",
        type=int,
        default=50,
        help="Number of packets to capture (default: 50)"
    )

    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=30,
        help="Maximum capture time in seconds (default: 30)"
    )

    args = parser.parse_args()

    if args.count < 1 or args.timeout < 1:
        parser.error("Count and timeout must be positive numbers.")

    print("PYTHON NETWORK TRAFFIC ANALYSER")
    print("=" * 40)
    print(f"Interface: {args.interface or 'Default interface'}")
    print(f"Packet limit: {args.count}")
    print(f"Timeout: {args.timeout} seconds")
    print("Capturing packet metadata only...")
    print("=" * 40)

    try:
        sniff(
            iface=args.interface,
            count=args.count,
            timeout=args.timeout,
            prn=analyse_packet,
            store=False
        )

    except PermissionError:
        print("\nPermission denied. Run with authorized capture privileges.")
        return

    except OSError as error:
        print(f"\nNetwork capture error: {error}")
        return

    except KeyboardInterrupt:
        print("\nCapture stopped by user.")

    finally:
        save_report()


if __name__ == "__main__":
    main()
