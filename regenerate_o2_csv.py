"""
regenerate_o2_csv.py

Reproduces o2_results.csv: runs the pipeline against zlib Tigress-CFF
level 50 at both -O0 and -O2 (repetition "_1_"), comparing recovered vs
ground-truth cyclomatic complexity. Also reports detection recall
separately from full within-2 recovery accuracy.

Run from the outer project directory:
    python3 -m cff_deobfuscator.regenerate_o2_csv
"""

import csv
import logging

logging.disable(logging.CRITICAL)

from .batch_eval import run_batch

CONFIGS = {
    "O0": {
        "obf_binary": "dataset/zlib/obfuscated/tigress/CFF/50/zlib_tigress_gcc_x64_CFF_50_1_O0.exe",
        "obf_json": "dataset/zlib/obfuscated/tigress/CFF/50/zlib_tigress_gcc_x64_CFF_50_1_O0.json",
        "plain_binary": "dataset/zlib/sources/zlib_gcc_x64_O0.exe",
        "plain_json": "dataset/zlib/sources/zlib_gcc_x64_O0.json",
    },
    "O2": {
        "obf_binary": "dataset/zlib/obfuscated/tigress/CFF/50/zlib_tigress_gcc_x64_CFF_50_1_O2.exe",
        "obf_json": "dataset/zlib/obfuscated/tigress/CFF/50/zlib_tigress_gcc_x64_CFF_50_1_O2.json",
        "plain_binary": "dataset/zlib/sources/zlib_gcc_x64_O2.exe",
        "plain_json": "dataset/zlib/sources/zlib_gcc_x64_O2.json",
    },
}


def main():
    results = {}
    for name, cfg in CONFIGS.items():
        stats = run_batch(cfg["obf_binary"], cfg["obf_json"], cfg["plain_binary"], cfg["plain_json"])
        detected = stats.targets - stats.no_dispatcher
        detection_recall_pct = round(100 * detected / stats.targets) if stats.targets else 0
        within2_pct = round(100 * stats.within2 / stats.compared) if stats.compared else 0
        results[name] = {
            "detection_recall_pct": detection_recall_pct,
            "within_2_accuracy_pct": within2_pct,
            "pure_cff_targets": stats.targets,
        }
        print(f"{name}: {results[name]} (raw: {stats.as_csv_row()})")

    with open("o2_results.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["metric", "O0", "O2"])
        for metric in ("detection_recall_pct", "within_2_accuracy_pct", "pure_cff_targets"):
            writer.writerow([metric, results["O0"][metric], results["O2"][metric]])
    print("Wrote o2_results.csv")


if __name__ == "__main__":
    main()
