"""
dispatcher.py

Structural detection of a control-flow-flattening dispatcher inside a
function's transition graph.

Tigress's flatten pass has a recognizable shape:

    entry:
        <init state var>
        goto dispatcher

    dispatcher:                <- huge in-degree (almost every real block
        switch(state_var) {       jumps back here)
          case C1: goto real_1
          case C2: goto real_2
          ...
        }

    real_1:
        ...
        state_var = <next state>
        goto dispatcher

    real_2:
        ...

So structurally: one node with in-degree >> average, and a majority of
*other* nodes each having the dispatcher as their unique successor.
This is obfuscator-agnostic (works for OLLVM's flattening too, which has
the same shape) which matters since the dataset includes both.

Confirmed against real Tigress -O0 output: the in-degree convergence
point found here can be a bare trampoline (`jmp`) hop away from the
actual comparison/jump-table logic -- resolve_switch_block() below
walks forward from it to find the real switch.
"""

import logging
import statistics
from collections import deque
from dataclasses import dataclass

import networkx as nx
import pyvex

log = logging.getLogger("cff.dispatcher")

# Tunable thresholds -- start conservative, loosen once we see false
# negatives on real dataset functions.
MIN_BLOCKS_FOR_CFF = 5          # tiny functions are never worth flagging
INDEGREE_ZSCORE_THRESHOLD = 2.0  # candidate must be this many std-devs above mean
MIN_BACK_EDGE_FRACTION = 0.5     # fraction of non-dispatcher blocks that funnel into it
SWITCH_SEARCH_MAX_BLOCKS = 30    # BFS hop budget for resolve_switch_block; 8 was too
                                 # shallow for some real -O0 functions (gf2_matrix_square,
                                 # bi_reverse, zcfree all needed >8 hops to reach the true
                                 # switch), confirmed safe to widen once the BFS was fixed
                                 # to stop chasing call/return targets (see resolve_switch_block)


@dataclass
class DispatcherInfo:
    dispatcher_addr: int
    real_blocks: set[int]       # blocks that funnel back into the dispatcher
    confidence: float           # 0-1, based on back-edge fraction
    in_degree: int


@dataclass
class SwitchSearchResult:
    switch_addr: int
    bound_const: int | None  # highest constant seen in a bounds-check compare on the path, if any
    chain_addrs: set  # every block visited while walking from the convergence point to the switch block


def _is_switch_block(irsb) -> bool:
    """
    A block is the real switch/comparison logic (as opposed to a plain
    trampoline hop) if either:
      - its terminating jump target is NOT a compile-time constant
        (an indirect jump -- the classic jump-table `jmp *table[state]`), or
      - it contains 2+ conditional Exit statements (an if/elif case chain).

    Confirmed against real -O0 output that a non-constant `next` is not
    sufficient on its own: a `ret` instruction's target (the return
    address popped off the stack) is also a non-constant temp, and a
    block ending Ijk_Ret was seen being misclassified as a jump-table
    switch as a direct result (e.g. zlib's gf2_matrix_square, bi_reverse
    at level 50 -O0). A switch's terminating jump is always an ordinary
    control transfer (Ijk_Boring), never a return or a call, so that is
    excluded explicitly rather than relying on Const-ness alone.

    Also confirmed necessary: the exit_count check must only count Exit
    statements whose OWN jumpkind is Ijk_Boring. A block with 2+ aligned
    SSE stores (`movaps`, common in a variadic function's va_start
    register-save-area prologue) gets one Ijk_SigSEGV Exit per store --
    VEX's semantic modeling of the CPU's real alignment-fault behavior
    for aligned SIMD instructions, not a conditional branch in the
    source at all. Counting these inflated exit_count past the >=2
    threshold for functions with no real if/elif chain whatsoever (e.g.
    sqlite's jsonPathSyntaxError: 8 Ijk_SigSEGV exits from 8 movaps
    stores, plus exactly 1 genuine Ijk_Boring exit -- nowhere near a
    real dispatcher, but exit_count() counted all 9 and misclassified
    this prologue block as a switch with 0 extractable cases).
    """
    if irsb.jumpkind != "Ijk_Boring":
        return False
    if not isinstance(irsb.next, pyvex.IRExpr.Const):
        return True
    exit_count = sum(1 for s in irsb.statements
                      if isinstance(s, pyvex.IRStmt.Exit) and s.jumpkind == "Ijk_Boring")
    return exit_count >= 2


def resolve_switch_block(proj, start_addr: int, max_blocks: int = SWITCH_SEARCH_MAX_BLOCKS) -> SwitchSearchResult | None:
    """
    The block with the anomalous in-degree (found by detect_dispatcher)
    is where real blocks converge, but confirmed against actual Tigress
    -O0 output: that convergence point can be a bare trampoline (`jmp`)
    that hands off to a bounds-check block, which itself hands off to
    the actual jump-table/comparison block. BFS forward through constant
    jump targets (both the default NEXT and any Exit branches) until we
    find a block matching the switch signature.

    Also opportunistically records the largest constant seen in a
    CmpLE/CmpLT-style comparison along the way -- for a jump-table
    dispatcher this is almost always the case-count bounds check
    (`if (state > N) goto default`), which cfg_recovery needs to know
    how many table entries to read.
    """
    visited = set()
    queue = deque([start_addr])
    bound_const = None

    while queue and len(visited) < max_blocks:
        addr = queue.popleft()
        if addr in visited:
            continue
        visited.add(addr)

        irsb = proj.factory.block(addr).vex
        tmp_defs = {s.tmp: s.data for s in irsb.statements
                    if isinstance(s, pyvex.IRStmt.WrTmp)}

        for stmt in irsb.statements:
            if isinstance(stmt, pyvex.IRStmt.WrTmp) and isinstance(stmt.data, pyvex.IRExpr.Binop):
                op = stmt.data.op
                if "CmpLE" in op or "CmpLT" in op:
                    for arg in stmt.data.args:
                        val = arg.con.value if isinstance(arg, pyvex.IRExpr.Const) else None
                        if val is not None and (bound_const is None or val > bound_const):
                            bound_const = val

        if _is_switch_block(irsb):
            return SwitchSearchResult(switch_addr=addr, bound_const=bound_const,
                                       chain_addrs=set(visited))

        for stmt in irsb.statements:
            if isinstance(stmt, pyvex.IRStmt.Exit) and stmt.jumpkind == "Ijk_Boring":
                queue.append(stmt.dst.value)
        # Chase the block's own fallthrough/jump target when it's an
        # ordinary control transfer (Ijk_Boring). A direct call's target
        # also shows up here as a constant `next` (Ijk_Call), and whether
        # to follow it is genuinely ambiguous: confirmed against real -O0
        # output that chasing it can walk into an unrelated PLT stub (e.g.
        # `free@plt` for zcfree, wrongly misidentified as a jump table),
        # but for another function (gzopen64) the real switch logic sits
        # behind exactly this kind of edge -- the compiler emitted it as
        # what angr's CFG labels a call to an outlined internal helper,
        # not a real external call. A PLT/import lookup distinguishes the
        # two cases precisely: an external call target resolves to a
        # named PLT stub or symbol, an internal one doesn't.
        if isinstance(irsb.next, pyvex.IRExpr.Const):
            nxt = irsb.next.con.value
            is_external_call = (irsb.jumpkind == "Ijk_Call"
                                 and (proj.loader.find_plt_stub_name(nxt) is not None
                                      or proj.loader.find_symbol(nxt) is not None))
            if irsb.jumpkind in ("Ijk_Boring", "Ijk_Call") and not is_external_call:
                if nxt != addr:  # don't chase a self-loop "invalid state" trap
                    queue.append(nxt)

    log.warning("resolve_switch_block: no switch-signature block found within "
                "%d hops of 0x%x", max_blocks, start_addr)
    return None


def build_transition_graph(angr_function) -> nx.DiGraph:
    """
    angr's Function object exposes .transition_graph already as a
    networkx DiGraph keyed by block/function addresses. We rebuild a
    clean address-keyed graph since transition_graph can mix Function
    and block nodes depending on call edges -- we only want intra-
    function block-to-block control flow (jumps/branches), not calls.
    """
    g = nx.DiGraph()
    for block in angr_function.blocks:
        g.add_node(block.addr)

    for src, dst, data in angr_function.transition_graph.edges(data=True):
        src_addr = getattr(src, "addr", src)
        dst_addr = getattr(dst, "addr", dst)
        # skip call/return edges -- CFF dispatchers are pure jump targets
        if data.get("type") in ("call", "return", "fake_return"):
            continue
        if src_addr in g and dst_addr in g:
            g.add_edge(src_addr, dst_addr)

    return g


def detect_dispatcher(angr_function, proj=None) -> DispatcherInfo | None:
    """
    proj is optional for backward compatibility, but strongly
    recommended: without it, this falls back to the old back-edge-
    funneling heuristic, which was found (by direct comparison against
    real non-CFF functions in the same binary) to have substantial
    overlap with genuinely flattened functions -- several non-CFF
    functions scored HIGHER than the minimum seen among real CFF
    functions, meaning no threshold on that metric alone can reliably
    separate the two classes.

    With proj supplied, candidates are instead confirmed by actually
    attempting to resolve a real switch structure downstream
    (resolve_switch_block) -- a jump table or a comparison chain with
    at least 3 cases. This is a far more specific, structural signal
    than graph statistics alone, and reuses the same extraction logic
    already trusted elsewhere in the pipeline.
    """
    g = build_transition_graph(angr_function)
    n = g.number_of_nodes()
    if n < MIN_BLOCKS_FOR_CFF:
        log.debug("Function too small (%d blocks) to plausibly be flattened", n)
        return None

    in_degrees = dict(g.in_degree())
    values = list(in_degrees.values())
    if len(values) < 2 or statistics.stdev(values) == 0:
        return None

    mean = statistics.mean(values)
    stdev = statistics.stdev(values)

    candidates = []
    for addr, indeg in in_degrees.items():
        z = (indeg - mean) / stdev
        if z >= INDEGREE_ZSCORE_THRESHOLD and indeg >= 3:
            candidates.append((addr, indeg, z))

    if not candidates:
        log.debug("No in-degree outlier found -- likely not flattened")
        return None

    candidates.sort(key=lambda c: c[1], reverse=True)

    if proj is not None:
        for disp_addr, disp_indeg, _ in candidates:
            search = resolve_switch_block(proj, disp_addr)
            if search is None:
                continue
            irsb = proj.factory.block(search.switch_addr).vex
            # Only Ijk_Boring exits are real conditional branches -- see
            # _is_switch_block's docstring for why (Ijk_SigSEGV exits from
            # aligned SSE stores inflate a naive count with no real cases).
            exit_count = sum(1 for s in irsb.statements
                              if isinstance(s, pyvex.IRStmt.Exit) and s.jumpkind == "Ijk_Boring")
            is_jump_table = not isinstance(irsb.next, pyvex.IRExpr.Const)
            if not (is_jump_table or exit_count >= 3):
                continue  # too few cases to be confident this is genuine flattening

            non_dispatcher_nodes = set(g.nodes) - {disp_addr}
            funneling = sum(1 for node in non_dispatcher_nodes
                             if set(g.successors(node)) == {disp_addr})
            back_edge_fraction = funneling / len(non_dispatcher_nodes) if non_dispatcher_nodes else 0
            real_blocks = {node for node in non_dispatcher_nodes
                            if g.successors(node) and set(g.successors(node)) == {disp_addr}}

            log.info("Dispatcher confirmed via switch resolution @ 0x%x "
                      "(in-degree=%d, switch kind=%s)",
                      disp_addr, disp_indeg, "jump_table" if is_jump_table else "exit_chain")
            return DispatcherInfo(dispatcher_addr=disp_addr, real_blocks=real_blocks,
                                   confidence=back_edge_fraction, in_degree=disp_indeg)
        log.debug("No candidate had a resolvable switch structure -- likely not flattened")
        return None

    # Fallback path (no proj supplied): old back-edge-funneling heuristic.
    disp_addr, disp_indeg, _ = candidates[0]

    predecessors = set(g.predecessors(disp_addr))
    non_dispatcher_nodes = set(g.nodes) - {disp_addr}
    if not non_dispatcher_nodes:
        return None

    funneling = 0
    for node in non_dispatcher_nodes:
        succs = set(g.successors(node))
        if succs == {disp_addr}:
            funneling += 1

    back_edge_fraction = funneling / len(non_dispatcher_nodes)

    if back_edge_fraction < MIN_BACK_EDGE_FRACTION:
        log.debug(
            "Dispatcher candidate 0x%x rejected: only %.0f%% of blocks funnel back",
            disp_addr, back_edge_fraction * 100,
        )
        return None

    real_blocks = {n for n in non_dispatcher_nodes if g.successors(n) and
                   set(g.successors(n)) == {disp_addr}}

    log.info(
        "Dispatcher found @ 0x%x (in-degree=%d, back-edge fraction=%.0f%%, %d real blocks)",
        disp_addr, disp_indeg, back_edge_fraction * 100, len(real_blocks),
    )

    return DispatcherInfo(
        dispatcher_addr=disp_addr,
        real_blocks=real_blocks,
        confidence=back_edge_fraction,
        in_degree=disp_indeg,
    )


def discover_real_blocks(g: nx.DiGraph, case_targets: set, chain_addrs: set, max_depth: int = 6) -> set:
    """
    Build the real-block set by walking FORWARD from each jump-table/
    exit-chain case target, following successors until each path either
    reaches back into the dispatcher chain or dead-ends.

    Confirmed necessary against real Tigress -O0 output: a jump-table
    case's target is not always a block that itself jumps back to the
    dispatcher. When the original code had an if/else, Tigress flattens
    it into: case-entry block (decides true/false) -> two child blocks
    (each sets its own next-state and loops back). The old approach --
    classifying "real" purely by "does this block's successor land in
    the chain" -- misses the entry block AND both children, since none
    of the three individually looks like the simple one-block case. This
    instead starts from what we already trust (the case-map targets) and
    walks forward, which correctly captures chains of any length.
    """
    real = set()
    for start in case_targets:
        if start in chain_addrs or start not in g:
            continue
        stack = [(start, 0)]
        seen_this_case = set()
        while stack:
            node, depth = stack.pop()
            if node in seen_this_case or node in chain_addrs:
                continue
            seen_this_case.add(node)
            real.add(node)
            if depth >= max_depth or node not in g:
                continue
            for succ in g.successors(node):
                if succ not in seen_this_case:
                    stack.append((succ, depth + 1))
    return real



