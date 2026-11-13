#!/usr/bin/env python3
"""Summarize recorded transfer batches; failed batches never become zero speeds."""

import argparse
import csv
import math
from pathlib import Path
import statistics
import sys


def summarize(path):
    groups = {}
    with path.open(newline="") as source:
        for row in csv.DictReader(source):
            key = (row["mode"], row["direction"], int(row["concurrency"]))
            group = groups.setdefault(key, {"rates": [], "bytes": 0, "seconds": 0.0, "failed": 0})
            if row["status"] == "failed":
                group["failed"] += 1
                continue
            if row["status"] != "ok":
                raise ValueError("unrecognized batch status")
            size, elapsed = int(row["bytes"]), float(row["seconds"])
            if size <= 0 or not math.isfinite(elapsed) or elapsed <= 0:
                raise ValueError("successful batches need positive bytes and finite duration")
            # Recompute from byte counts and time, rather than rounded display speeds.
            group["rates"].append(size / (1 << 20) / elapsed)
            group["bytes"] += size
            group["seconds"] += elapsed
    for (mode, direction, concurrency), group in groups.items():
        rates = group["rates"]
        count = len(rates)
        yield {
            "mode": mode,
            "direction": direction,
            "concurrency": concurrency,
            "valid_batches": count,
            "observed_failed_batches": group["failed"],
            "mean_mib_per_second": f"{statistics.mean(rates):.6f}" if count else "",
            "sample_sd_mib_per_second": f"{statistics.stdev(rates):.6f}" if count > 1 else "",
            "median_mib_per_second": f"{statistics.median(rates):.6f}" if count else "",
            "total_bytes": group["bytes"],
            "total_seconds": f"{group['seconds']:.6f}",
            "aggregate_mib_per_second": f"{group['bytes'] / (1 << 20) / group['seconds']:.6f}" if count else "",
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("samples", type=Path, help="CSV with one row per observed transfer batch")
    args = parser.parse_args()
    rows = list(summarize(args.samples))
    if not rows:
        parser.error("no transfer batches found")
    writer = csv.DictWriter(sys.stdout, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)


if __name__ == "__main__":
    main()
