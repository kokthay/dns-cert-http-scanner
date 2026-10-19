#!/usr/bin/env python3
"""Extract saved IPv4 addresses, falling back to IPv6, in one pass.

Reads ROOT/SHARD/RANK-DOMAIN/a.json and, only if needed, aaaa.json.
Writes rank, domain, ips as JSON Lines, sorted by numeric rank.
Uses all unique addresses from the selected family in answer order.
Successful IPv6 results are included even if A failed; these are fallback
addresses, not proof that a domain is IPv6-only. No DNS queries are made.
"""

import argparse
from collections import Counter
import ipaddress
import json
import os
from pathlib import Path
import sys


def domain_folders(root):
    folders = []
    with os.scandir(root) as shards:
        for shard in shards:
            if (not shard.is_dir(follow_symlinks=False)
                    or len(shard.name) != 3 or not shard.name.isdigit()):
                continue
            with os.scandir(shard.path) as domains:
                for entry in domains:
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    rank, separator, domain = entry.name.partition("-")
                    if separator and rank.isdigit() and domain:
                        folders.append((int(rank), domain, entry.path))
    folders.sort(key=lambda row: (row[0], row[1], row[2]))
    return folders


def read_addresses(path, record_type):
    try:
        with path.open(encoding="utf-8-sig") as source:
            result = json.load(source)["results"][record_type]
        status = result.get("status", "UNKNOWN")
        if status != "NOERROR":
            return [], status if isinstance(status, str) else "MALFORMED"
        answers = (result.get("data") or {}).get("answers") or []
        if not isinstance(answers, list):
            raise ValueError("Invalid answers list")
        address_type = ipaddress.IPv4Address if record_type == "A" else ipaddress.IPv6Address
        ips, seen = [], set()
        for answer in answers:
            if not isinstance(answer, dict):
                raise ValueError("Invalid answer entry")
            if answer.get("type") != record_type:
                continue
            value = answer.get("answer")
            if not isinstance(value, str):
                continue
            try:
                ip = str(address_type(value))
            except ValueError:
                continue
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)
        return ips, status
    except FileNotFoundError:
        return [], "MISSING"
    except (ValueError, KeyError, TypeError, AttributeError):
        return [], "MALFORMED"
    except OSError:
        return [], "READ_ERROR"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="Path to results/domains")
    parser.add_argument("output", type=Path, help="Combined IPv4/IPv6 JSON Lines file")
    parser.add_argument("--skipped-output", type=Path,
                        help="Default: skipped_domain.json beside output")
    args = parser.parse_args()
    root = args.root.expanduser().resolve()
    output = args.output.expanduser().resolve()
    skipped = (args.skipped_output.expanduser().resolve() if args.skipped_output
               else output.parent / "skipped_domain.json")
    if not root.is_dir():
        parser.error(f"Directory does not exist: {root}")
    if output == skipped:
        parser.error("Successful and skipped output files must be different.")
    for destination in (output, skipped):
        if destination == root or root in destination.parents:
            parser.error("Place output files outside the input domains directory.")

    print("Finding domain folders...", file=sys.stderr, flush=True)
    folders = domain_folders(root)
    if not folders:
        parser.error("No SHARD/RANK-DOMAIN folders found; check the root path.")
    counts = Counter()
    with output.open("w", encoding="utf-8") as target, skipped.open("w", encoding="utf-8") as missing:
        for index, (rank, domain, folder) in enumerate(folders, 1):
            folder = Path(folder)
            ips, a_status = read_addresses(folder / "a.json", "A")
            if ips:
                counts["IPv4"] += 1
            else:
                ips, _ = read_addresses(folder / "aaaa.json", "AAAA")
                if ips:
                    counts["IPv6 fallback"] += 1
                    if a_status != "NOERROR":
                        counts["IPv6 fallback with failed/missing/malformed A"] += 1
            row = {"rank": rank, "domain": domain}
            if ips:
                row["ips"] = ips
                target.write(json.dumps(row) + "\n")
                counts["Written"] += 1
            else:
                missing.write(json.dumps(row) + "\n")
                counts["Skipped"] += 1
            if index % 10000 == 0:
                print(f"Processed {index:,}/{len(folders):,}; written {counts['Written']:,}",
                      file=sys.stderr, flush=True)

    print(f"Domain folders: {len(folders):,}")
    for label in ("Written", "IPv4", "IPv6 fallback",
                  "IPv6 fallback with failed/missing/malformed A", "Skipped"):
        print(f"{label}: {counts[label]:,}")
    print(f"Output: {output}")
    print(f"Skipped output: {skipped}")


if __name__ == "__main__":
    main()
