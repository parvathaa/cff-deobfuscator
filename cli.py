"""
cli.py

Usage (v1 scope: single obfuscated binary, matched against its plain
counterpart, Tigress CFF, -O0):

    python -m cff_deobfuscator.cli \
        --obf-binary dataset/zlib/obfuscated/tigress/CFF/50/zlib_tigress_gcc_x64_CFF_50_3_O0.exe \
        --obf-json   dataset/zlib/obfuscated/tigress/CFF/50/zlib_tigress_gcc_x64_CFF_50_3_O0.json \
        --plain-binary dataset/zlib/sources/zlib_gcc_x64_O0.exe \
        --plain-json   dataset/zlib/sources/zlib_gcc_x64_O0.json

Only functions marked obfuscated=true in --obf-json are processed.
Matching plain function is looked up by name in --plain-json (names are
preserved even in the obfuscated JSON's ground truth, per the dataset's
own documentation, since binaries are stripped but json keeps symbols).
"""

import argparse
import json
import logging
import sys

from . import cfg_recovery
from . import evaluate
from .loader import BinaryContext

log = logging.getLogger("cff.cli")


def main():
    parser = argparse.ArgumentParser(description="CFF deobfuscation pipeline (v1)")
    parser.add_argument("--obf-binary", required=True)
    parser.add_argument("--obf-json", required=True)
    parser.add_argument("--plain-binary", required=True)
    parser.add_argument("--plain-json", required=True)
    parser.add_argument("--limit", type=int, default=None,
                         help="cap number of functions processed (debugging)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    log.info("Loading obfuscated binary...")
    obf_ctx = BinaryContext(args.obf_binary, args.obf_json)

    log.info("Loading plain binary...")
    plain_ctx = BinaryContext(args.plain_binary, args.plain_json)

    targets = obf_ctx.get_obfuscated_targets()
    # v1 only handles pure CFF -- silently including a mix1/mix2 function
    # (CFF stacked with encodearith/opaque/split) would produce a
    # misleading "recovery failed" result that's actually just out of
    # scope, not a bug. Filter explicitly so failures we see are real.
    cff_only = [t for t in targets if t.obfu_passes == ["cff"]]
    if len(cff_only) != len(targets):
        log.info("Filtered %d targets down to %d pure-CFF targets "
                  "(excluded functions with other/additional obfuscation passes)",
                  len(targets), len(cff_only))
    targets = cff_only
    if args.limit:
        targets = targets[: args.limit]
    log.info("%d obfuscated functions to process", len(targets))

    results = []
    for target in targets:
        angr_func = obf_ctx.get_angr_function(target)
        if angr_func is None:
            continue

        recovery = cfg_recovery.recover_function_cfg(obf_ctx.proj, angr_func)
        if recovery.dispatcher_addr is None or recovery.recovered_cfg.number_of_nodes() == 0:
            log.warning("Skipping eval for %s: recovery failed or no dispatcher", target.name)
            continue

        plain_target = plain_ctx.functions.get(target.name)
        if plain_target is None:
            log.warning("No matching plain function for %s, skipping eval", target.name)
            continue
        plain_func = plain_ctx.get_angr_function(plain_target)
        if plain_func is None:
            continue

        gt_cfg = evaluate.get_ground_truth_cfg(plain_ctx.proj, plain_ctx.cfg, plain_func.addr)
        eval_result = evaluate.evaluate_recovery(recovery.recovered_cfg, gt_cfg, target.name)
        results.append(eval_result)

        log.info("%s: node_recall=%.2f edge_precision=%.2f edge_recall=%.2f f1=%.2f",
                  target.name, eval_result.node_recall, eval_result.edge_precision,
                  eval_result.edge_recall, eval_result.edge_f1)

    summary = evaluate.summarize(results)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
