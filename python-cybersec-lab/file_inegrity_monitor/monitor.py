
import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
BASELINE_FILE = BASE_DIR / "baseline.json"
REPORT_DIR = BASE_DIR / "reports"


def calculate_sha256(file_path):
    digest = hashlib.sha256()

    with file_path.open("rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            digest.update(chunk)

    return digest.hexdigest()


def create_snapshot(directory):
    snapshot = {}

    for file_path in directory.rglob("*"):
        if file_path.is_symlink() or not file_path.is_file():
            continue

        relative_path = str(file_path.relative_to(directory))

        try:
            snapshot[relative_path] = {
                "sha256": calculate_sha256(file_path),
                "size": file_path.stat().st_size
            }
        except (PermissionError, OSError) as error:
            print(f"[SKIPPED] {relative_path}: {error}")

    return snapshot


def create_baseline(directory):
    snapshot = create_snapshot(directory)

    baseline = {
        "directory": str(directory.resolve()),
        "created_at": datetime.now().isoformat(),
        "files": snapshot
    }

    BASELINE_FILE.write_text(
        json.dumps(baseline, indent=4),
        encoding="utf-8"
    )

    print(f"\nBaseline created: {BASELINE_FILE}")
    print(f"Files recorded: {len(snapshot)}")


def scan_directory(directory):
    if not BASELINE_FILE.exists():
        print("No baseline found. Create one first.")
        return

    baseline = json.loads(
        BASELINE_FILE.read_text(encoding="utf-8")
    )

    if baseline["directory"] != str(directory.resolve()):
        print("ERROR: This is not the directory used for the baseline.")
        return

    old_files = baseline["files"]
    new_files = create_snapshot(directory)

    old_names = set(old_files)
    new_names = set(new_files)

    results = []

    for name in sorted(new_names - old_names):
        results.append({
            "file": name,
            "status": "NEW"
        })

    for name in sorted(old_names - new_names):
        results.append({
            "file": name,
            "status": "DELETED"
        })

    for name in sorted(old_names & new_names):
        if old_files[name]["sha256"] != new_files[name]["sha256"]:
            results.append({
                "file": name,
                "status": "MODIFIED",
                "old_sha256": old_files[name]["sha256"],
                "new_sha256": new_files[name]["sha256"]
            })
        else:
            results.append({
                "file": name,
                "status": "UNCHANGED"
            })

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = REPORT_DIR / f"integrity_report_{timestamp}.json"

    report = {
        "scanned_directory": str(directory.resolve()),
        "scan_time": datetime.now().isoformat(),
        "results": results
    }

    report_file.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8"
    )

    print("\nFILE INTEGRITY MONITOR")
    print("=" * 40)

    if not results:
        print("No files found.")
    else:
        for result in results:
            print(f"[{result['status']}] {result['file']}")

    print("=" * 40)
    print(f"Report saved: {report_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Python File Integrity Monitor"
    )

    parser.add_argument(
        "action",
        choices=["baseline", "scan"],
        help="Create a baseline or scan for changes"
    )

    parser.add_argument(
        "directory",
        help="Directory you own or are authorized to monitor"
    )

    args = parser.parse_args()
    directory = Path(args.directory).expanduser().resolve()

    if not directory.is_dir():
        print("ERROR: Directory does not exist.")
        return

    if args.action == "baseline":
        create_baseline(directory)
    else:
        scan_directory(directory)


if __name__ == "__main__":
    main()
