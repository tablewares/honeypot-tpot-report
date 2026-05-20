import json
from collections import Counter, defaultdict
from datetime import datetime
import argparse


def parse_file(path):
    results = []

    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                results.append(data)
            except json.JSONDecodeError:
                continue

    return results


def extract_family(record):
    try:
        return (
            record["full_response"]["data"]["attributes"]
            .get("popular_threat_classification", {})
            .get("suggested_threat_label")
        )
    except (KeyError, TypeError):
        return None


def extract_attributes(record):
    try:
        return record["full_response"]["data"]["attributes"]
    except (KeyError, TypeError):
        return {}


def aggregate(results):
    summary = {
        "total": 0,
        "found": 0,
        "not_found": 0,
        "errors": 0,
        "malicious_files": 0,
        "clean_files": 0,
        "hashes": set(),
        "malicious_counts": [],
        "timeline": defaultdict(int),
        "families": Counter(),

        # 👇 NEW
        "suspicious_files": 0,
        "harmless_files": 0,
        "file_types": Counter(),
        "engine_hits": Counter(),
        "top_hashes": Counter(),
        "detection_ratios": Counter(),
    }

    for r in results:
        summary["total"] += 1

        status = r.get("status")
        timestamp = r.get("timestamp")
        hash_ = r.get("hash")

        if hash_:
            summary["hashes"].add(hash_)

        # timeline
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp)
                key = dt.strftime("%Y-%m-%d %H:%M")
                summary["timeline"][key] += 1
            except Exception:
                pass

        if status == "Found":
            summary["found"] += 1

            stats = r.get("stats") or {}
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)

            summary["malicious_counts"].append(malicious)

            if malicious > 0:
                summary["malicious_files"] += 1
                if hash_:
                    summary["top_hashes"][hash_] += malicious
            else:
                summary["clean_files"] += 1

            if suspicious > 0:
                summary["suspicious_files"] += 1

            if harmless > 0:
                summary["harmless_files"] += 1

            # detection ratio bucket (e.g. "5/70")
            total_engines = sum(stats.values()) if stats else 0
            if total_engines:
                ratio = f"{malicious}/{total_engines}"
                summary["detection_ratios"][ratio] += 1

            # attributes
            attr = extract_attributes(r)

            # file type
            file_type = attr.get("type_description") or attr.get("type_tag")
            if file_type:
                summary["file_types"][file_type] += 1

            # AV engine results
            results_dict = attr.get("last_analysis_results", {})
            for engine, res in results_dict.items():
                if res.get("category") == "malicious":
                    summary["engine_hits"][engine] += 1

            # malware family
            family = extract_family(r)
            if family:
                summary["families"][family] += 1

        elif status == "Not Found":
            summary["not_found"] += 1
            if r.get("full_response", {}).get("error"):
                summary["errors"] += 1

    return summary


def print_report(summary):
    print("=" * 50)
    print("SCAN SUMMARY")
    print("=" * 50)

    print(f"Total entries:        {summary['total']}")
    print(f"Unique hashes:        {len(summary['hashes'])}")
    print(f"Found:                {summary['found']}")
    print(f"Not Found:            {summary['not_found']}")
    print(f"Errors:               {summary['errors']}")
    print()

    print("Detection:")
    print(f"  Malicious files:    {summary['malicious_files']}")
    print(f"  Clean files:        {summary['clean_files']}")
    print(f"  Suspicious files:   {summary['suspicious_files']}")
    print(f"  Harmless flagged:   {summary['harmless_files']}")

    if summary["malicious_counts"]:
        avg = sum(summary["malicious_counts"]) / len(summary["malicious_counts"])
        print(f"  Avg detections:     {avg:.2f}")

    print("\nTop Malware Families:")
    for family, count in summary["families"].most_common(10):
        print(f"  {family:30} {count}")

    print("\nTop File Types:")
    for t, count in summary["file_types"].most_common(10):
        print(f"  {t:30} {count}")

    print("\nTop AV Engines (by detections):")
    for eng, count in summary["engine_hits"].most_common(10):
        print(f"  {eng:25} {count}")

    print("\nDetection Ratios:")
    for ratio, count in summary["detection_ratios"].most_common(10):
        print(f"  {ratio:10} {count}")

    print("\nMost Malicious Hashes:")
    for h, score in summary["top_hashes"].most_common(10):
        print(f"  {h} ({score} detections)")

    print("\nActivity timeline (per minute):")
    for k in sorted(summary["timeline"]):
        print(f"  {k} -> {summary['timeline'][k]} events")


def pipeline(path):
    data = parse_file(path)
    summary = aggregate(data)
    print_report(summary)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VirusTotal parser (enhanced)")
    parser.add_argument("file", help="Input JSONL file")
    args = parser.parse_args()

    pipeline(args.file)
