"""
evaluate.py

Compares a recovered CFG against ground truth. The dataset gives us the
plain (unobfuscated) source/binary for the same function, so ground
truth isn't hand-labeled -- it's the real CFG of the compiled original,
recovered the normal way via angr CFGFast (no dispatcher games needed).

We report standard graph-recovery metrics rather than exact isomorphism,
since block boundaries can differ slightly between the plain and
obfuscated compilations even when the *logical* structure is identical
(different register allocation, instruction selection, etc. cause
different basic-block splits). Edge-level precision/recall against a
best-effort block alignment is the metric that survives this noise.
"""

import logging
from dataclasses import dataclass

import networkx as nx

log = logging.getLogger("cff.evaluate")


@dataclass
class EvalResult:
    function_name: str
    node_recall: float
    edge_precision: float
    edge_recall: float
    edge_f1: float
    notes: str = ""


def get_ground_truth_cfg(plain_proj, plain_cfg, plain_function_addr) -> nx.DiGraph:
    func = plain_cfg.kb.functions.function(addr=plain_function_addr)
    if func is None:
        raise ValueError(f"Could not resolve plain function @ 0x{plain_function_addr:x}")
    from . import dispatcher as disp_mod  # local import to avoid a cycle at module load
    return disp_mod.build_transition_graph(func)


def _normalize_by_topology(g: nx.DiGraph) -> nx.DiGraph:
    """
    Relabel nodes 0..N-1 in a stable order (DFS preorder from entry) so
    we can compare two graphs built from different address spaces
    (obfuscated binary vs plain binary) node-for-node. This is a
    heuristic alignment -- it works well when block count and branch
    structure roughly match, which holds for -O0 where flattening
    doesn't otherwise restructure blocks. It will need a smarter
    (e.g. graph-edit-distance-based) alignment for -O2 or heavily
    diverged recoveries -- flagged as a known limitation below.
    """
    if g.number_of_nodes() == 0:
        return nx.DiGraph()
    entry = min(g.nodes)  # lowest address as a proxy for entry block
    order = list(nx.dfs_preorder_nodes(g, source=entry))
    # include any nodes DFS didn't reach (disconnected pieces from
    # unresolved blocks) at the end, in address order
    order += sorted(n for n in g.nodes if n not in order)
    remap = {addr: i for i, addr in enumerate(order)}
    return nx.relabel_nodes(g, remap)


def evaluate_recovery(recovered_cfg: nx.DiGraph, ground_truth_cfg: nx.DiGraph,
                       function_name: str = "") -> EvalResult:
    rec_norm = _normalize_by_topology(recovered_cfg)
    gt_norm = _normalize_by_topology(ground_truth_cfg)

    gt_nodes = set(gt_norm.nodes)
    rec_nodes = set(rec_norm.nodes)
    node_recall = len(gt_nodes & rec_nodes) / len(gt_nodes) if gt_nodes else 0.0

    gt_edges = set(gt_norm.edges)
    rec_edges = set(rec_norm.edges)

    tp = len(gt_edges & rec_edges)
    edge_precision = tp / len(rec_edges) if rec_edges else 0.0
    edge_recall = tp / len(gt_edges) if gt_edges else 0.0
    edge_f1 = (2 * edge_precision * edge_recall / (edge_precision + edge_recall)
               if (edge_precision + edge_recall) > 0 else 0.0)

    notes = ""
    if abs(len(gt_nodes) - len(rec_nodes)) > 0.3 * max(len(gt_nodes), 1):
        notes = ("WARNING: node count diverges >30% between recovered and "
                 "ground truth -- topology-order alignment above is probably "
                 "unreliable here; treat edge metrics with caution")
        log.warning("%s: %s", function_name, notes)

    return EvalResult(
        function_name=function_name,
        node_recall=node_recall,
        edge_precision=edge_precision,
        edge_recall=edge_recall,
        edge_f1=edge_f1,
        notes=notes,
    )


def summarize(results: list[EvalResult]) -> dict:
    if not results:
        return {}
    n = len(results)
    return {
        "count": n,
        "mean_node_recall": sum(r.node_recall for r in results) / n,
        "mean_edge_precision": sum(r.edge_precision for r in results) / n,
        "mean_edge_recall": sum(r.edge_recall for r in results) / n,
        "mean_edge_f1": sum(r.edge_f1 for r in results) / n,
        "flagged_count": sum(1 for r in results if r.notes),
    }
