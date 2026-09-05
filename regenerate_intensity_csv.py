"""
regenerate_intensity_csv.py

Reproduces batch_results_by_intensity.csv: runs the pipeline against the
"_1_" repetition of every available zlib Tigress-CFF intensity level
(-O0), comparing recovered vs ground-truth cyclomatic complexity for
each pure-CFF function. Skips level 20 -- the dataset only ships a
stray .exe with no matching ground-truth JSON at that level, not a
pipeline limitation.

Run from the outer project directory:
    python3 -m cff_deobfuscator.regenerate_intensity_csv
"""

import csv
import logging

logging.disable(logging.CRITICAL)

from .batch_eval import run_batch

LEVELS = [10, 30, 40, 50, 60, 70, 80, 90, 100]  # 20 excluded: dataset only ships
                                                 # repetitions "_2_"/"_7_" for this
                                                 # level, not "_1_", and "_2_" has no
                                                 # matching .exe either -- a genuine
                                                 # dataset gap, not a pipeline issue
PLAIN_BINARY = "dataset/zlib/sources/zlib_gcc_x64_O0.exe"
PLAIN_JSON = "dataset/zlib/sources/zlib_gcc_x64_O0.json"


def main():
    rows = []
    for level in LEVELS:
        obf_binary = f"dataset/zlib/obfuscated/tigress/CFF/{level}/zlib_tigress_gcc_x64_CFF_{level}_1_O0.exe"
        obf_json = f"dataset/zlib/obfuscated/tigress/CFF/{level}/zlib_tigress_gcc_x64_CFF_{level}_1_O0.json"
        try:
            stats = run_batch(obf_binary, obf_json, PLAIN_BINARY, PLAIN_JSON)
        except Exception as exc:
            print(f"level {level}: skipped, {type(exc).__name__}: {exc}")
            continue
        row = stats.as_csv_row(level=level)
        rows.append(row)
        print(f"level {level}: {row}")

    fieldnames = ["level", "targets", "no_dispatcher", "compared", "exact", "within2", "mean_abs_diff"]
    with open("batch_results_by_intensity.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row[k] for k in fieldnames})
    print("Wrote batch_results_by_intensity.csv")


if __name__ == "__main__":
    main()
