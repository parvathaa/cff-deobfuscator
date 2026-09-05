"""
batch_eval.py

Reproducible batch validation: runs the recovery pipeline against every
pure-CFF target in an obfuscated binary and compares recovered cyclomatic
complexity (edges - nodes + 2) against each function's plain counterpart.

This is the metric actually reported in the dissertation (Section 3.2:
node/edge alignment across separate compilations was found unreliable
since a compiler is free to split blocks differently even for identical
source logic -- cyclomatic complexity is comparatively insensitive to
that while remaining sensitive to real branching differences).

This module previously existed only as ad-hoc, uncommitted scripts run
by hand (see demo_send_tree.py for the single-function version) -- the
CSVs in this repo (batch_results_by_intensity.csv, o2_results.csv,
sqlite_generalization_results.csv) were produced that way and were not
reproducible from checked-in code. This module + the scripts/ wrappers
that call it close that gap.
"""

import logging
from dataclasses import dataclass, field

from . import cfg_recovery
from . import dispatcher as disp_mod
from .loader import BinaryContext

log = logging.getLogger("cff.batch_eval")


def cyclomatic_complexity(g) -> int:
    return g.number_of_edges() - g.number_of_nodes() + 2


@dataclass
class FunctionResult:
    name: str
    status: str  # "no_dispatcher" | "extract_failed" | "compared"
    recovered_complexity: int | None = None
    ground_truth_complexity: int | None = None
    abs_diff: int | None = None


@dataclass
class BatchStats:
    targets: int = 0
    no_dispatcher: int = 0
    extraction_failed: int = 0
    compared: int = 0
    exact: int = 0
    within2: int = 0
    mean_abs_diff: float | None = None
    per_function: list[FunctionResult] = field(default_factory=list)

    def as_csv_row(self, **extra_cols) -> dict:
        row = {
            "targets": self.targets,
            "no_dispatcher": self.no_dispatcher,
            "compared": self.compared,
            "exact": self.exact,
            "within2": self.within2,
            "mean_abs_diff": round(self.mean_abs_diff, 2) if self.mean_abs_diff is not None else "",
        }
        row.update(extra_cols)
        return row


def ground_truth_complexity(plain_ctx: BinaryContext, name: str) -> int | None:
    plain_target = plain_ctx.functions.get(name)
    if plain_target is None:
        return None
    plain_func = plain_ctx.get_angr_function(plain_target)
    if plain_func is None:
        return None
    gt_cfg = disp_mod.build_transition_graph(plain_func)
    return cyclomatic_complexity(gt_cfg)


def run_batch(obf_binary: str, obf_json: str, plain_binary: str, plain_json: str,
              limit: int | None = None) -> BatchStats:
    log.info("Loading obfuscated binary %s", obf_binary)
    obf_ctx = BinaryContext(obf_binary, obf_json)
    log.info("Loading plain binary %s", plain_binary)
    plain_ctx = BinaryContext(plain_binary, plain_json)

    targets = [t for t in obf_ctx.get_obfuscated_targets() if t.obfu_passes == ["cff"]]
    if limit:
        targets = targets[:limit]

    stats = BatchStats(targets=len(targets))
    diffs = []

    for i, target in enumerate(targets, 1):
        angr_func = obf_ctx.get_angr_function(target)
        if angr_func is None:
            stats.no_dispatcher += 1
            stats.per_function.append(FunctionResult(target.name, "no_dispatcher"))
            continue

        try:
            result = cfg_recovery.recover_function_cfg(obf_ctx.proj, angr_func)
        except Exception:
            log.exception("Unhandled exception recovering %s", target.name)
            result = None

        if result is None or result.dispatcher_addr is None:
            stats.no_dispatcher += 1
            stats.per_function.append(FunctionResult(target.name, "no_dispatcher"))
            continue

        # recover_function_cfg always adds the function's own entry address
        # as a node regardless of outcome, so recovered_cfg.number_of_nodes()
        # is never 0 even when zero real blocks were resolved -- confirmed
        # directly against gzopen64, whose case map came back empty (the
        # bounds-check block supplying the jump table's size sits on a path
        # this particular function's dispatcher chain doesn't traverse) yet
        # still reported a 1-node, 0-edge "recovered" graph with no error
        # set. real_block_count is the reliable signal for a genuinely
        # empty/degenerate recovery.
        if (result.stats.get("error") is not None
                or not result.stats.get("real_block_count")):
            stats.extraction_failed += 1
            stats.per_function.append(FunctionResult(target.name, "extract_failed"))
            continue

        gt = ground_truth_complexity(plain_ctx, target.name)
        if gt is None:
            log.warning("No matching plain function for %s, skipping comparison", target.name)
            continue

        rec = cyclomatic_complexity(result.recovered_cfg)
        diff = abs(rec - gt)
        diffs.append(diff)
        stats.compared += 1
        if diff == 0:
            stats.exact += 1
        if diff <= 2:
            stats.within2 += 1
        stats.per_function.append(FunctionResult(target.name, "compared", rec, gt, diff))

        log.info("[%d/%d] %-28s recovered=%d ground_truth=%d diff=%d",
                  i, len(targets), target.name, rec, gt, diff)

    if diffs:
        stats.mean_abs_diff = sum(diffs) / len(diffs)

    return stats
