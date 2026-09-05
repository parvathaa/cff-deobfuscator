"""
regenerate_sqlite_csv.py

Reproduces sqlite_generalization_results.csv: runs the pipeline,
unmodified, against sqlite (Tigress CFF level 50, -O0, repetition "_1_")
to test generalisation beyond the zlib codebase it was built and tuned
against.

Run from the outer project directory:
    python3 -m cff_deobfuscator.regenerate_sqlite_csv
"""

import csv
import logging

logging.disable(logging.CRITICAL)

from .batch_eval import run_batch

OBF_BINARY = "dataset/sqlite/obfuscated/tigress/CFF/50/sqlite_tigress_gcc_x64_CFF_50_1_O0.exe"
OBF_JSON = "dataset/sqlite/obfuscated/tigress/CFF/50/sqlite_tigress_gcc_x64_CFF_50_1_O0.json"
PLAIN_BINARY = "dataset/sqlite/sources/sqlite_gcc_x64_O0.exe"
PLAIN_JSON = "dataset/sqlite/sources/sqlite_gcc_x64_O0.json"


def main():
    stats = run_batch(OBF_BINARY, OBF_JSON, PLAIN_BINARY, PLAIN_JSON)
    extraction_failed = stats.targets - stats.no_dispatcher - stats.compared
    detection_recall_pct = round(100 * (stats.targets - stats.no_dispatcher) / stats.targets) if stats.targets else 0
    exact_match_pct = round(100 * stats.exact / stats.compared) if stats.compared else 0
    within2_pct = round(100 * stats.within2 / stats.compared) if stats.compared else 0

    rows = [
        ("pure_cff_targets", stats.targets),
        ("no_dispatcher_missed", stats.no_dispatcher),
        ("extraction_failed_excluded", extraction_failed),
        ("genuinely_compared", stats.compared),
        ("exact_match", stats.exact),
        ("within_2", stats.within2),
        ("detection_recall_pct", detection_recall_pct),
        ("exact_match_pct", exact_match_pct),
        ("within_2_pct", within2_pct),
    ]
    for metric, value in rows:
        print(f"{metric}: {value}")

    with open("sqlite_generalization_results.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["metric", "value"])
        writer.writerows(rows)
    print("Wrote sqlite_generalization_results.csv")


if __name__ == "__main__":
    main()
