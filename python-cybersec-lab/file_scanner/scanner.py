
import os
import hashlib
import json
import argparse
from pathlib import Path
from datetime import datetime

# File extensions worth investigating
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".bat",
    ".cmd", ".ps1", ".vbs", ".jar",
    ".elf", ".sh"
}

# Directories we don't need to scan
IGNORED_DIRECTORIES = {
    ".venv", ".git", "__pycache__"
}


def calculate_hash(file_path):
    """Calculate the SHA-256 hash of a file."""

    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:
            for chunk in iter(lambda: file.read(4096), b""):
                sha256.update(chunk)

        return sha256.hexdigest()

    except (OSError, PermissionError) as error:
        print(f"[!] Cannot read {file_path}: {error}")
        return None


def load_previous_report(report_path):
    """Load hashes from the previous scan."""

    try:
        with open(report_path, "r") as report:
            data = json.load(report)

        return {
            item["path"]: item["sha256"]
            for item in data.get("files", [])
            if item.get("sha256")
        }

    except (OSError, json.JSONDecodeError, KeyError, TypeError):
        return {}


def scan_directory(directory, report_path):
    """Scan files and identify changes."""

    directory = Path(directory).resolve()
    report_path = Path(report_path).resolve()

    if not directory.is_dir():
        raise ValueError("The specified path is not a directory.")

    previous_hashes = load_previous_report(report_path)
    results = []

    print(f"\n[*] Scanning: {directory}\n")

    for root, dirs, files in os.walk(directory, followlinks=False):

        dirs[:] = [
            name for name in dirs
            if name not in IGNORED_DIRECTORIES
        ]

        for filename in files:

            file_path = Path(root) / filename

            if file_path.resolve() == report_path:
                continue

            if file_path.is_symlink() or not file_path.is_file():
                continue

            file_hash = calculate_hash(file_path)

            if file_hash is None:
                continue

            extension = file_path.suffix.lower()

            old_hash = previous_hashes.get(str(file_path))

            if old_hash is None:
                status = "NEW"
            elif old_hash != file_hash:
                status = "CHANGED"
            else:
                status = "UNCHANGED"

            suspicious = extension in SUSPICIOUS_EXTENSIONS

            result = {
                "path": str(file_path),
                "size": file_path.stat().st_size,
                "extension": extension,
                "sha256": file_hash,
                "status": status,
                "suspicious_extension": suspicious
            }

            results.append(result)

            print(f"[{status}] {file_path}")

            if suspicious:
                print("    [!] Extension requires investigation")

    report = {
        "scan_date": datetime.now().isoformat(),
        "directory": str(directory),
        "total_files": len(results),
        "files": results
    }

    with open(report_path, "w") as output:
        json.dump(report, output, indent=4)

    print("\n[+] Scan completed!")
    print(f"[+] Files scanned: {len(results)}")
    print(f"[+] Report saved to: {report_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Python File System Security Scanner"
    )

    parser.add_argument(
        "directory",
        nargs="?",
        default=".",
        help="Directory to scan"
    )

    parser.add_argument(
        "--report",
        default="scan_report.json",
        help="Output report filename"
    )

    args = parser.parse_args()

    try:
        scan_directory(args.directory, args.report)
    except (ValueError, OSError) as error:
        print(f"[!] Error: {error}")


if __name__ == "__main__":
    main()
