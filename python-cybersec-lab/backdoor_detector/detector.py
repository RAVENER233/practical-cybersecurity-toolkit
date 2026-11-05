
import json
import os
from datetime import datetime
from pathlib import Path

import psutil


BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports"

SERVICE_DIRECTORIES = [
    Path("/etc/systemd/system"),
    Path.home() / ".config/systemd/user",
    Path.home() / ".config/autostart",
]

REVIEW_KEYWORDS = [
    "backdoor",
    "reverse-shell",
    "reverseshell",
    "meterpreter",
    "payload",
    "netcat",
    "cryptominer",
    "hidden-service",
    "socat",
]


def inspect_listening_ports():
    findings = []

    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        print("[WARNING] Some network connections require elevated privileges.")
        return findings
    except OSError as error:
        print(f"[WARNING] Could not inspect network connections: {error}")
        return findings

    for connection in connections:
        if connection.status != psutil.CONN_LISTEN:
            continue

        process_name = "Unknown"

        if connection.pid is not None:
            try:
                process_name = psutil.Process(connection.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        local_address = (
            f"{connection.laddr.ip}:{connection.laddr.port}"
            if connection.laddr
            else "Unknown"
        )

        protocol = (
            "TCP" if connection.type == 1
            else "UDP" if connection.type == 2
            else "Other"
        )

        findings.append({
            "protocol": protocol,
            "local_address": local_address,
            "pid": connection.pid,
            "process": process_name
        })

    return findings


def inspect_startup_entries():
    findings = []

    for directory in SERVICE_DIRECTORIES:
        if not directory.exists():
            continue

        try:
            for entry in directory.iterdir():
                if entry.is_symlink() or not entry.is_file():
                    continue

                name = entry.name.lower()

                matched_keywords = [
                    keyword for keyword in REVIEW_KEYWORDS
                    if keyword in name
                ]

                findings.append({
                    "file": str(entry),
                    "name": entry.name,
                    "requires_review": bool(matched_keywords),
                    "matched_keywords": matched_keywords
                })

        except PermissionError:
            print(f"[WARNING] Permission denied: {directory}")
        except OSError as error:
            print(f"[WARNING] Could not inspect {directory}: {error}")

    return findings


def save_report(ports, startup_entries):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    report = {
        "scan_time": datetime.now().isoformat(),
        "machine": os.uname().nodename,
        "listening_ports": ports,
        "startup_entries": startup_entries,
        "summary": {
            "listening_port_count": len(ports),
            "startup_entry_count": len(startup_entries),
            "startup_entries_requiring_review": sum(
                item["requires_review"] for item in startup_entries
            )
        },
        "warning": (
            "These are investigation leads, not proof of a backdoor. "
            "Legitimate software may use unusual ports or service names."
        )
    }

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = REPORT_DIR / f"backdoor_report_{timestamp}.json"

    report_path.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8"
    )

    return report_path


def main():
    print("\nLINUX BACKDOOR DETECTION TOOL")
    print("=" * 45)

    print("\nInspecting listening network ports...")
    ports = inspect_listening_ports()

    for item in ports:
        print(
            f"[LISTENING] {item['protocol']} "
            f"{item['local_address']} | "
            f"PID: {item['pid']} | "
            f"Process: {item['process']}"
        )

    print("\nInspecting startup entries...")
    startup_entries = inspect_startup_entries()

    for item in startup_entries:
        status = (
            "REVIEW" if item["requires_review"]
            else "FOUND"
        )
        print(f"[{status}] {item['name']}")

    report_path = save_report(ports, startup_entries)

    print("\n" + "=" * 45)
    print(f"Listening ports found: {len(ports)}")
    print(f"Startup entries found: {len(startup_entries)}")
    print(f"Report saved: {report_path}")
    print("\nReview any flagged entries manually.")
    print("A flag is not proof of malicious activity.")


if __name__ == "__main__":
    main()
