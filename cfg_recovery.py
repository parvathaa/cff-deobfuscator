"""
cfg_recovery.py

Orchestrates dispatcher.py + state_analysis.py to produce a recovered
"logical" CFG for a flattened function: real blocks connected directly
to each other (dispatcher edges collapsed away), matching the shape the
CFG would have had before Tigress flattened it.

Algorithm:
  1. Detect the dispatcher convergence point (dispatcher.py).
  2. Resolve the real switch block downstream of it, and extract the
     state variable location + switch shape (state_analysis.py).
  3. Build a map: dispatcher_case_value -> real_block_addr. For an
     if/elif chain this comes from the switch block's own Exit guards
     (static, no solver needed -- the dispatcher itself isn't
     obfuscated). For a jump table, this comes from reading the actual
     table entries out of the binary's .rodata.
  4. For each real block B: determine what state value(s) B sets before
     jumping back to the dispatcher (state_analysis.analyze_block).
  5. Edge B -> real_block[state_value] for each resolved value. Multiple
     resolved values on one block = a recovered branch (this is the
     symbolic-fallback case recovering hidden control flow).
"""

import logging
from dataclasses import dataclass, field

import networkx as nx
import pyvex

from . import dispatcher as disp_mod
from . import state_analysis as sa

log = logging.getLogger("cff.recovery")


@dataclass
class RecoveryResult:
    function_addr: int
    recovered_cfg: nx.DiGraph
    dispatcher_addr: int | None
    unresolved_blocks: list[int] = field(default_factory=list)
    stats: dict = field(default_factory=dict)


def build_case_map(proj, switch_info: sa.SwitchInfo) -> dict[int, int]:
    """
    Read the switch block's own comparison/jump-table logic to build
    {state_value: real_block_addr}. This is not itself obfuscated --
    Tigress needs it to stay simple and fast -- so it's plain static
    reading, no solver required.
    """
    if switch_info.kind == "jump_table":
        return _build_case_map_jumptable(proj, switch_info)
    return _build_case_map_exit_chain(proj, switch_info)


def _build_case_map_exit_chain(proj, switch_info: sa.SwitchInfo) -> dict[int, int]:
    irsb = proj.factory.block(switch_info.switch_addr).vex
    tmp_defs = {s.tmp: s.data for s in irsb.statements if isinstance(s, pyvex.IRStmt.WrTmp)}

    case_map = {}
    for stmt in irsb.statements:
        # Ijk_Boring only -- an Ijk_SigSEGV exit (VEX's alignment-fault
        # modeling for an aligned SSE store, e.g. movaps in a variadic
        # function's va_start prologue) is not a real case guard. These
        # happen to use CmpNE rather than CmpEQ in practice, so
        # _extract_compare_const already filters most of them out, but
        # the jumpkind check is the actual semantic signal and is
        # checked explicitly rather than relied on incidentally.
        if not isinstance(stmt, pyvex.IRStmt.Exit) or stmt.jumpkind != "Ijk_Boring":
            continue
        const_val = _extract_compare_const(stmt.guard, tmp_defs)
        if const_val is not None:
            case_map[const_val] = stmt.dst.value

    if not case_map:
        log.warning("Exit-chain switch @ 0x%x: no comparison constants found",
                    switch_info.switch_addr)
    return case_map


def _build_case_map_jumptable(proj, switch_info: sa.SwitchInfo) -> dict[int, int]:
    """
    Read table_size 4-byte signed entries starting at table_base directly
    out of the binary's mapped memory, matching the shape confirmed
    against real Tigress -O0 output:

        target[i] = table_base + sign_extend32(entries[i])
    """
    if switch_info.table_base is None or switch_info.table_size is None:
        log.warning("Jump table @ 0x%x: missing table_base or table_size "
                    "(bound wasn't found during switch-block search) -- "
                    "cannot build case map", switch_info.switch_addr)
        return {}

    case_map = {}
    for i in range(switch_info.table_size):
        entry_addr = switch_info.table_base + i * 4
        try:
            raw = proj.loader.memory.load(entry_addr, 4)
        except KeyError:
            log.warning("Jump table @ 0x%x: entry %d at 0x%x not mapped, stopping",
                        switch_info.switch_addr, i, entry_addr)
            break
        entry = int.from_bytes(raw, byteorder="little", signed=True)
        target = switch_info.table_base + entry
        case_map[i] = target

    return case_map


def _extract_compare_const(guard_expr, tmp_defs):
    """Guard is typically CmpEQ(state_tmp, Const) or CmpEQ(Const, state_tmp)."""
    guard = guard_expr
    if isinstance(guard, pyvex.IRExpr.RdTmp):
        guard = tmp_defs.get(guard.tmp)
    if not isinstance(guard, pyvex.IRExpr.Binop) or "CmpEQ" not in guard.op:
        return None
    for arg in guard.args:
        val = sa._resolve_const(arg, tmp_defs)
        if val is not None:
            return val
    return None


def recover_function_cfg(proj, angr_function) -> RecoveryResult:
    disp_info = disp_mod.detect_dispatcher(angr_function, proj=proj)
    if disp_info is None:
        log.info("Function @ 0x%x: no dispatcher detected, not flattened "
                  "(or detection missed it) -- returning original CFG untouched",
                  angr_function.addr)
        return RecoveryResult(
            function_addr=angr_function.addr,
            recovered_cfg=disp_mod.build_transition_graph(angr_function),
            dispatcher_addr=None,
        )

    loc, switch_info = sa.extract_state_location(proj, disp_info.dispatcher_addr)
    if loc is None or switch_info is None:
        log.error("Function @ 0x%x: dispatcher found but state variable "
                   "extraction failed -- aborting recovery for this function",
                   angr_function.addr)
        return RecoveryResult(
            function_addr=angr_function.addr,
            recovered_cfg=nx.DiGraph(),
            dispatcher_addr=disp_info.dispatcher_addr,
            stats={"error": "state_location_extraction_failed"},
        )

    case_map = build_case_map(proj, switch_info)

    # Recompute real blocks against the whole dispatcher chain, not just
    # the single convergence node -- confirmed against real output that
    # detect_dispatcher's narrower set silently drops blocks that skip
    # the trampoline and jump straight into the bounds-check/switch link.
    # Discover real blocks by walking forward from each case-map target,
    # not by checking each block's own successor -- see discover_real_blocks
    # docstring for why (branching cases need this).
    chain_addrs = switch_info.chain_addrs or {disp_info.dispatcher_addr}
    full_graph = disp_mod.build_transition_graph(angr_function)
    real_blocks = disp_mod.discover_real_blocks(full_graph, set(case_map.values()), chain_addrs)
    if len(real_blocks) > len(disp_info.real_blocks):
        log.info("Discovered real-block set: %d blocks (was %d under the old "
                  "narrow heuristic), following %d case targets forward through "
                  "the graph", len(real_blocks), len(disp_info.real_blocks), len(case_map))

    recovered = nx.DiGraph()
    for block_addr in real_blocks:
        recovered.add_node(block_addr)
        # Branch edges: any direct successor that's also a real block is a
        # genuine intra-case control-flow edge (e.g. an if/else Tigress
        # flattened inside one case) -- not a state-variable transition,
        # just the original branch structure, still visible in the IR.
        for succ in full_graph.successors(block_addr):
            if succ in real_blocks:
                recovered.add_edge(block_addr, succ)

    unresolved = []
    method_counts = {"constant": 0, "constant_chain": 0, "symbolic": 0, "unresolved": 0}

    # Static constant-propagation across each case's branch chain, from
    # its true entry point. Confirmed necessary against real batch
    # results: a case's actual state assignment can happen in an earlier
    # block in the same chain (e.g. the entry sets a register to a
    # literal, an unconditional child does unrelated work and never
    # touches it again before exiting) -- analyzing the terminal block
    # in isolation cannot see that earlier assignment. This carries a
    # known constant forward across blocks at the IR level, with no
    # execution involved, so it cannot hit the state-tracking bug class
    # that broke an earlier, reverted, full symbolic whole-chain attempt.
    case_entries = set(case_map.values()) & real_blocks
    resolved_terminals = set()
    for entry_addr_case in case_entries:
        chain_results = sa.resolve_case_chain_static(
            proj, entry_addr_case, chain_addrs, real_blocks, full_graph, loc)
        for terminal_addr, values in chain_results.items():
            if terminal_addr not in real_blocks:
                continue
            resolved_terminals.add(terminal_addr)
            method_counts["constant_chain"] += 1
            for val in values:
                target = case_map.get(val)
                if target is None:
                    log.debug("Static chain from 0x%x, terminal 0x%x: resolved "
                              "state value %d has no matching dispatcher case",
                              entry_addr_case, terminal_addr, val)
                    continue
                recovered.add_edge(terminal_addr, target)

    # For any terminal block the static pass didn't resolve, fall back
    # to the existing, proven per-block analysis (constant fastpath then
    # single-block symbolic execution) exactly as before.
    for block_addr in real_blocks:
        if block_addr in resolved_terminals:
            continue
        succs = set(full_graph.successors(block_addr))
        if not (succs and succs.issubset(chain_addrs)):
            continue

        result = sa.analyze_block(proj, block_addr, loc)
        method_counts[result.method] += 1

        if not result.resolved_values:
            unresolved.append(block_addr)
            continue

        for val in result.resolved_values:
            target = case_map.get(val)
            if target is None:
                log.debug("Block 0x%x resolved state value %d has no matching "
                          "dispatcher case -- possibly the function's exit state",
                          block_addr, val)
                continue
            recovered.add_edge(block_addr, target)

    entry_addr = angr_function.addr
    recovered.add_node(entry_addr)

    log.info(
        "Function @ 0x%x recovery done: switch_kind=%s, %d real blocks, %d edges, "
        "%d unresolved, method breakdown=%s",
        angr_function.addr, switch_info.kind, len(real_blocks),
        recovered.number_of_edges(), len(unresolved), method_counts,
    )

    return RecoveryResult(
        function_addr=angr_function.addr,
        recovered_cfg=recovered,
        dispatcher_addr=disp_info.dispatcher_addr,
        unresolved_blocks=unresolved,
        stats={
            "real_block_count": len(real_blocks),
            "edge_count": recovered.number_of_edges(),
            "method_counts": method_counts,
            "dispatcher_confidence": disp_info.confidence,
            "switch_kind": switch_info.kind,
            "case_count": len(case_map),
        },
    )
