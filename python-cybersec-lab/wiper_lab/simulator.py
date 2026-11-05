
import hashlib
import json
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SANDBOX = BASE_DIR / "sandbox"
ORIGINALS = SANDBOX / "originals"
SIMULATED_WIPE = SANDBOX / "simulated_wipe"
REPORTS = BASE_DIR / "reports"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def prepare_sandbox():
    ORIGINALS.mkdir(parents=True, exist_ok=True)
    SIMULATED_WIPE.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)

    samples = {
        "sample_document.txt": (
            "This is a disposable cybersecurity research file.\n"
        ),
        "sample_notes.txt": (
            "This file is used to study simulated data destruction.\n"
        )
    }

    for filename, content in samples.items():
        sample_path = ORIGINALS / filename

        if not sample_path.exists():
            sample_path.write_text(content, encoding="utf-8")


def simulate_wipe():
    prepare_sandbox()

    results = []

    for original in ORIGINALS.iterdir():
        if original.is_symlink() or not original.is_file():
            continue

        original_data = original.read_bytes()

        # Create a damaged COPY. Never alter the original.
        damaged_data = bytes(len(original_data))

        output_path = SIMULATED_WIPE / original.name
        output_path.write_bytes(damaged_data)

        original_hash = sha256(original_data)
        damaged_hash = sha256(damaged_data)

        results.append({
            "file": original.name,
            "original_sha256": original_hash,
            "simulated_sha256": damaged_hash,
            "original_preserved": original.exists(),
            "damage_detected": original_hash != damaged_hash
        })

    report = {
        "created_at": datetime.now().isoformat(),
        "simulation": "Wiper malware impact simulation",
        "note": "Only generated copies were modified.",
        "results": results
    }

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = REPORTS / f"wiper_report_{timestamp}.json"

    report_path.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8"
    )

    print("\nWIPER RESEARCH SIMULATOR")
    print("=" * 45)

    for result in results:
        status = (
            "DAMAGE SIMULATED"
            if result["damage_detected"]
            else "NO CHANGE"
        )

        print(f"[{status}] {result['file']}")
        print(f"Original preserved: {result['original_preserved']}")

    print("=" * 45)
    print(f"Report saved: {report_path}")


if __name__ == "__main__":
    simulate_wipe()
