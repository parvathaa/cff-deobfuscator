"""
state_analysis.py

Core of the pipeline: for each "real" block that jumps back into the
dispatcher, determine which dispatcher-state value(s) it sets, so we can
map dispatcher-edge -> real successor block.

Two-tier approach:

  1. FAST PATH (constant propagation): inspect the block's VEX IR
     directly. If the state variable is assigned a literal constant
     right before the jump back to the dispatcher (the common case --
     this is what Tigress emits for a normal, non-branching real block),
     we read it straight off the IR. No solver needed.

  2. FALLBACK (symbolic execution): if the assignment is data-dependent
     (e.g. the block ends with an opaque predicate, a computed next-state
     via arithmetic/XOR on another variable, or the flattening pass
     merged an original if/else into the state computation), we can't
     read a literal. Instead we symbolically execute from the block's
     entry to its exit and ask the solver which concrete values the
     state expression can take. Each solution is a distinct successor
     edge in the recovered CFG -- this is also how we recover cases
     where flattening hid an actual *branch*, not just a straight-line
     re-entry.

Both tiers resolve against a `StateLocation`, extracted from the real
switch block (dispatcher.resolve_switch_block finds it -- the in-degree
convergence point detect_dispatcher finds can be a bare trampoline hop
away from the actual comparison/jump-table logic; confirmed against
real Tigress -O0 output).
"""

import logging
from dataclasses import dataclass, field

import claripy
import pyvex

log = logging.getLogger("cff.state")

MAX_SYMBOLIC_SOLUTIONS = 32  # sanity cap; a legit switch case count won't exceed this
# for realistic zlib/sqlite functions. If we hit the cap, it's a sign the
# state variable was chosen wrong or there's a real unbounded loop merged in.


@dataclass
class StateLocation:
    """
    Where the dispatcher-state value lives. Tigress/OLLVM almost always
    spill it to a stack slot (not a plain register) because it has to
    survive every real block's execution. Confirmed against real -O0
    Tigress output that the base register is rbp (frame pointer), not
    rsp -- so this tracks whichever base register the IR actually used,
    rather than assuming sp.
    kind: "reg" or "stack"
    reg_offset: VEX register file offset, if kind == "reg"
    base_reg_offset: VEX register file offset of the base register
        (rbp or rsp) used in the address computation, if kind == "stack"
    stack_delta: constant offset added to the base register, if kind == "stack"
    """
    kind: str
    reg_offset: int | None = None
    base_reg_offset: int | None = None
    stack_delta: int | None = None
    size_bytes: int = 4  # Tigress default state var is a 32-bit int
    # Arithmetic offset between a value STORED at this location and the
    # value the dispatcher actually uses as its jump-table/case index.
    # Confirmed necessary: some functions read the register via an
    # arithmetic transform of the true stack value (e.g. rax = state - 3),
    # not a bare copy. Default 0 covers the common case (bare copy or
    # direct stack access) with no behaviour change.
    value_offset: int = 0


@dataclass
class SwitchInfo:
    switch_addr: int
    kind: str  # "exit_chain" | "jump_table"
    table_base: int | None = None
    table_size: int | None = None
    chain_addrs: set | None = None


@dataclass
class BlockStateResult:
    block_addr: int
    resolved_values: set[int] = field(default_factory=set)
    method: str = "unresolved"   # "constant" | "symbolic" | "unresolved"


def extract_state_location(proj, dispatcher_addr: int):
    """
    Returns (StateLocation, SwitchInfo) or (None, None).

    Resolves the real switch block first (it can be one or two hops
    downstream of the in-degree convergence point detect_dispatcher
    finds -- confirmed against real Tigress -O0 output where the
    convergence point was a bare `jmp` trampoline), then branches on
    its shape:
      - indirect NEXT (jmp *table[state])  -> jump-table extraction
      - 2+ Exit statements                  -> if/elif chain extraction
    """
    from . import dispatcher as disp_mod

    search = disp_mod.resolve_switch_block(proj, dispatcher_addr)
    if search is None:
        return None, None

    switch_addr = search.switch_addr
    irsb = proj.factory.block(switch_addr).vex
    tmp_defs = {s.tmp: s.data for s in irsb.statements if isinstance(s, pyvex.IRStmt.WrTmp)}

    if not isinstance(irsb.next, pyvex.IRExpr.Const):
        result = _extract_jumptable_state(irsb, tmp_defs)
        if result is None:
            log.warning("Switch block @ 0x%x looked like a jump table but "
                        "pattern extraction failed", switch_addr)
            return None, None
        root, table_base = result

        # If the trace bottomed out at a bare register read, the switch
        # block itself never computed that register's value -- check the
        # other blocks in the same dispatcher chain (e.g. a bounds-check
        # block) for where it was actually populated, since it's often a
        # transient copy of the true, stack-resident state variable.
        value_offset = 0
        if isinstance(root, pyvex.IRExpr.Get):
            other_chain_blocks = (search.chain_addrs or set()) - {switch_addr}
            better_root, better_irsb, better_tmp_defs, offset = _resolve_register_via_chain(
                proj, root.offset, other_chain_blocks)
            if better_root is not None:
                log.info("Switch @ 0x%x: register read resolved further via "
                         "another chain block (was a transient copy, offset=%d)",
                         switch_addr, offset)
                root, irsb, tmp_defs = better_root, better_irsb, better_tmp_defs
                value_offset = offset

        loc = _root_to_location(root, tmp_defs, irsb, proj.arch)
        if loc is None:
            return None, None
        loc.value_offset = value_offset
        table_size = (search.bound_const + 1) if search.bound_const is not None else None
        switch_info = SwitchInfo(switch_addr=switch_addr, kind="jump_table",
                                  table_base=table_base, table_size=table_size,
                                  chain_addrs=search.chain_addrs)
        return loc, switch_info

    guard_tmps = [s.guard for s in irsb.statements if isinstance(s, pyvex.IRStmt.Exit)]
    root = None
    for g in guard_tmps:
        root = _trace_root(g, tmp_defs)
        if root is not None:
            break
    if root is None:
        log.warning("Could not trace state variable root in exit-chain switch @ 0x%x",
                    switch_addr)
        return None, None
    loc = _root_to_location(root, tmp_defs, irsb, proj.arch)
    if loc is None:
        return None, None
    switch_info = SwitchInfo(switch_addr=switch_addr, kind="exit_chain",
                              chain_addrs=search.chain_addrs)
    return loc, switch_info


def _root_to_location(root, tmp_defs, irsb, arch):
    if isinstance(root, pyvex.IRExpr.Get):
        return StateLocation(kind="reg", reg_offset=root.offset,
                              size_bytes=root.result_size(irsb.tyenv) // 8)
    if isinstance(root, pyvex.IRExpr.Load):
        base_reg_offset, delta = _extract_stack_delta(root.addr, tmp_defs, arch)
        if base_reg_offset is None:
            log.warning("State var is a Load but address isn't a simple "
                        "Get(sp/bp)+const -- likely -O2 or pointer-indirect state")
            return None
        return StateLocation(kind="stack", base_reg_offset=base_reg_offset,
                              stack_delta=delta,
                              size_bytes=root.result_size(irsb.tyenv) // 8)
    return None


def _trace_root(expr, tmp_defs):
    """Follow a tmp back to its defining Get or Load, descending Binop's first arg."""
    seen = set()
    cur = expr
    while True:
        if isinstance(cur, pyvex.IRExpr.RdTmp):
            if cur.tmp in seen:
                return None
            seen.add(cur.tmp)
            if cur.tmp not in tmp_defs:
                return None
            cur = tmp_defs[cur.tmp]
            continue
        if isinstance(cur, (pyvex.IRExpr.Get, pyvex.IRExpr.Load)):
            return cur
        if isinstance(cur, pyvex.IRExpr.Binop):
            return _trace_root(cur.args[0], tmp_defs)
        return None


def _resolve(expr, tmp_defs):
    """Unwrap a single RdTmp hop to its definition, else return expr unchanged."""
    if isinstance(expr, pyvex.IRExpr.RdTmp):
        return tmp_defs.get(expr.tmp)
    return expr


def _trace_root_with_offset(expr, tmp_defs):
    """
    Like _trace_root, but also accumulates any constant Add/Sub
    encountered while descending through Binops, so the caller knows
    the arithmetic relationship between the returned root and the
    original expression.

    Confirmed necessary against real output: for some functions the
    dispatcher computes its jump-table index as `rax = stack_value - 3`,
    not a bare copy of the stack-resident state variable. Finding the
    stack location alone (via plain _trace_root) is not sufficient --
    a literal value later written to that stack slot must have this
    same offset applied before it corresponds to the index the
    dispatcher will actually use.

    Returns (root, offset) such that, for a literal value V written to
    the root's location, the dispatcher-computed index is (V + offset).
    Returns (None, None) if the arithmetic shape isn't a simple constant
    Add/Sub chain this function knows how to track.
    """
    cur = expr
    offset = 0
    seen = set()
    while True:
        if isinstance(cur, pyvex.IRExpr.RdTmp):
            if cur.tmp in seen or cur.tmp not in tmp_defs:
                return None, None
            seen.add(cur.tmp)
            cur = tmp_defs[cur.tmp]
            continue
        if isinstance(cur, (pyvex.IRExpr.Get, pyvex.IRExpr.Load)):
            return cur, offset
        if isinstance(cur, pyvex.IRExpr.Binop):
            a0, a1 = cur.args[0], cur.args[1]
            const_val = a1.con.value if isinstance(a1, pyvex.IRExpr.Const) else None
            if const_val is not None and "Sub" in cur.op:
                offset -= const_val
                cur = a0
                continue
            if const_val is not None and "Add" in cur.op:
                offset += const_val
                cur = a0
                continue
            return None, None
        return None, None


def _resolve_register_via_chain(proj, reg_offset, chain_block_addrs):
    """
    If the switch block reads a register whose value isn't computed
    within the switch block itself, check whether one of the OTHER
    blocks in the dispatcher chain (e.g. a bounds-check block) writes
    to that same register.

    Confirmed necessary against real output: the switch block can
    simply re-read a register that an earlier chain block populated
    from the true state variable's real location, a stack slot, via
    something like `mov rax, [rbp-0x10]` in the bounds-check block,
    immediately before the jump-table switch block runs. Without this,
    the trace stops at the bare register read and incorrectly treats
    a transient copy as the state variable's real location.

    Returns (resolved_root_expr, its_block_irsb, its_tmp_defs, value_offset)
    if found, else (None, None, None, 0). The irsb/tmp_defs are returned
    alongside the root since it can come from a different block than the
    switch block itself, and any RdTmp references within it must be
    resolved against the tmp_defs of the block it actually appeared in.
    value_offset is the arithmetic adjustment between a value stored at
    the root's location and the value the dispatcher actually uses
    (see _trace_root_with_offset).
    """
    for addr in chain_block_addrs:
        irsb = proj.factory.block(addr).vex
        tmp_defs = {s.tmp: s.data for s in irsb.statements if isinstance(s, pyvex.IRStmt.WrTmp)}
        last_put_data = None
        for stmt in irsb.statements:
            if isinstance(stmt, pyvex.IRStmt.Put) and stmt.offset == reg_offset:
                last_put_data = stmt.data
        if last_put_data is None:
            continue
        traced, offset = _trace_root_with_offset(last_put_data, tmp_defs)
        if traced is not None:
            return traced, irsb, tmp_defs, offset
    return None, None, None, 0


def _extract_jumptable_state(irsb, tmp_defs):
    """
    Recognize the GCC/-O0 jump-table shape confirmed against real dataset
    output:

        target = table_base + sign_extend32(Load32(table_base + (state << 2)))

    i.e. irsb.next traces to Add(entry_chain, Const(table_base)), where
    entry_chain unwraps through zero/sign-extend Unops down to
    Load(Add(Const(table_base), Shl(state_tmp, 2))).

    Returns (state_root_expr, table_base) or None.
    """
    nxt = irsb.next
    cur = _resolve(nxt, tmp_defs) if isinstance(nxt, pyvex.IRExpr.RdTmp) else nxt
    if not (isinstance(cur, pyvex.IRExpr.Binop) and cur.op.startswith("Iop_Add")):
        return None

    const_side, other = None, None
    for x in cur.args:
        xr = _resolve(x, tmp_defs) if isinstance(x, pyvex.IRExpr.RdTmp) else x
        if isinstance(xr, pyvex.IRExpr.Const):
            const_side = xr.con.value
        else:
            other = x
    if const_side is None or other is None:
        return None
    table_base = const_side

    cur2 = _resolve(other, tmp_defs) if isinstance(other, pyvex.IRExpr.RdTmp) else other
    hops = 0
    while cur2 is not None and not isinstance(cur2, pyvex.IRExpr.Load) and hops < 8:
        if isinstance(cur2, pyvex.IRExpr.Unop):
            arg = cur2.args[0]
            cur2 = _resolve(arg, tmp_defs) if isinstance(arg, pyvex.IRExpr.RdTmp) else arg
        elif isinstance(cur2, pyvex.IRExpr.RdTmp):
            cur2 = tmp_defs.get(cur2.tmp)
        else:
            break
        hops += 1

    if not isinstance(cur2, pyvex.IRExpr.Load):
        return None

    addr_r = _resolve(cur2.addr, tmp_defs) if isinstance(cur2.addr, pyvex.IRExpr.RdTmp) else cur2.addr
    if not (isinstance(addr_r, pyvex.IRExpr.Binop) and addr_r.op.startswith("Iop_Add")):
        return None

    shl_expr = None
    for x in addr_r.args:
        xr = _resolve(x, tmp_defs) if isinstance(x, pyvex.IRExpr.RdTmp) else x
        if isinstance(xr, pyvex.IRExpr.Binop) and xr.op.startswith("Iop_Shl"):
            shl_expr = xr
    if shl_expr is None:
        return None

    state_operand = shl_expr.args[0]
    state_root = _resolve(state_operand, tmp_defs) if isinstance(state_operand, pyvex.IRExpr.RdTmp) else state_operand
    if isinstance(state_root, pyvex.IRExpr.RdTmp):
        state_root = _trace_root(state_root, tmp_defs)
    return state_root, table_base


def _extract_stack_delta(addr_expr, tmp_defs, arch):
    """
    Trace an address expression to Add(Get(sp_or_bp_offset), Const(delta))
    and return (base_reg_offset, delta). Checks both sp and bp since
    -O0 Tigress output uses the frame pointer (rbp), confirmed against
    real dataset binaries -- not sp as originally assumed.
    Returns (None, None) if the address isn't this simple shape.
    """
    expr = addr_expr
    if isinstance(expr, pyvex.IRExpr.RdTmp):
        expr = tmp_defs.get(expr.tmp)
    if expr is None:
        return None, None

    candidate_offsets = {arch.sp_offset, arch.bp_offset}

    if isinstance(expr, pyvex.IRExpr.Get) and expr.offset in candidate_offsets:
        return expr.offset, 0

    if isinstance(expr, pyvex.IRExpr.Binop) and expr.op.startswith("Iop_Add"):
        a, b = expr.args
        a_def = tmp_defs.get(a.tmp) if isinstance(a, pyvex.IRExpr.RdTmp) else a
        b_def = tmp_defs.get(b.tmp) if isinstance(b, pyvex.IRExpr.RdTmp) else b

        base_side, const_side = None, None
        if isinstance(a_def, pyvex.IRExpr.Get) and a_def.offset in candidate_offsets:
            base_side, const_side = a_def, b_def
        elif isinstance(b_def, pyvex.IRExpr.Get) and b_def.offset in candidate_offsets:
            base_side, const_side = b_def, a_def

        if base_side is not None and isinstance(const_side, pyvex.IRExpr.Const):
            val = const_side.con.value
            bits = const_side.con.size
            if val >= (1 << (bits - 1)):
                val -= (1 << bits)
            return base_side.offset, val

    return None, None


def _read_state_value(state, loc: StateLocation):
    """
    Read the state variable's current value out of a live SimState.
    Assumes loc.stack_delta is resolved relative to the CURRENT block's
    base register (fine within one basic block -- rbp/rsp don't move
    mid-block for the functions we're targeting since Tigress doesn't
    inject stack-altering ops into real blocks).
    """
    if loc.kind == "reg":
        return state.registers.load(loc.reg_offset, loc.size_bytes)
    if loc.stack_delta is None or loc.base_reg_offset is None:
        return None
    base_val = state.registers.load(loc.base_reg_offset, state.arch.bytes)
    addr = base_val + loc.stack_delta
    return state.memory.load(addr, loc.size_bytes, endness=state.arch.memory_endness)


def analyze_block(proj, block_addr: int, loc: StateLocation) -> BlockStateResult:
    result = BlockStateResult(block_addr=block_addr)

    const_val = _try_constant_fastpath(proj, block_addr, loc)
    if const_val is not None:
        # Apply value_offset: a literal value STORED at loc's location is
        # not necessarily the value the dispatcher actually indexes with,
        # if this state variable is read via an arithmetic transform (see
        # _trace_root_with_offset). Default value_offset=0 for the common
        # case (bare copy) means this is a no-op everywhere else.
        result.resolved_values = {const_val + loc.value_offset}
        result.method = "constant"
        return result

    log.debug("Block 0x%x: no constant found, falling back to symbolic exec", block_addr)
    values = _symbolic_fallback(proj, block_addr, loc)
    if values:
        result.resolved_values = {v + loc.value_offset for v in values}
        result.method = "symbolic"
    return result


def _try_constant_fastpath(proj, block_addr: int, loc: StateLocation) -> int | None:
    """
    Look for a WrTmp/Put or Store statement writing a literal Const
    directly to the state location, at the end of the block. Covers the
    overwhelming majority of real blocks in a Tigress-flattened function,
    since most original blocks had no data dependency on their own
    "next case" -- the compiler just hardcodes it.
    """
    irsb = proj.factory.block(block_addr).vex
    tmp_defs = {}
    last_const = None

    for stmt in irsb.statements:
        if isinstance(stmt, pyvex.IRStmt.WrTmp):
            tmp_defs[stmt.tmp] = stmt.data

        if loc.kind == "reg" and isinstance(stmt, pyvex.IRStmt.Put):
            if stmt.offset == loc.reg_offset:
                val = _resolve_const(stmt.data, tmp_defs)
                last_const = val if val is not None else None

        if loc.kind == "stack" and loc.stack_delta is not None and \
                isinstance(stmt, pyvex.IRStmt.Store):
            store_base, store_delta = _extract_stack_delta(stmt.addr, tmp_defs, proj.arch)
            if store_base == loc.base_reg_offset and store_delta == loc.stack_delta:
                val = _resolve_const(stmt.data, tmp_defs)
                last_const = val if val is not None else None

    return last_const


def _resolve_const(expr, tmp_defs):
    if isinstance(expr, pyvex.IRExpr.Const):
        return expr.con.value
    if isinstance(expr, pyvex.IRExpr.RdTmp):
        src = tmp_defs.get(expr.tmp)
        if src is not None:
            return _resolve_const(src, tmp_defs)
    return None


def _symbolic_fallback(proj, block_addr: int, loc: StateLocation) -> set[int]:
    """
    Step a fresh symbolic state through the block and ask the solver for
    every concrete value the state expression can take at block exit.
    This naturally recovers cases where a real block still contains a
    genuine branch after flattening (e.g. flattening applied on top of
    an if/else -- the "next state" is itself conditional), which the
    constant fastpath cannot see by definition.

    Confirmed against real batch results (30 zlib functions): blank_state
    at a mid-function address leaves rbp/rsp SYMBOLIC (angr doesn't know
    the frame was ever set up), so a stack-relative state read like
    [rbp-0x48] becomes a read from an unconstrained symbolic address --
    which angr can only model as "could be anything", producing bogus
    32-solution results with no relation to the block's actual logic.
    Pinning the base register to a fixed concrete sentinel first makes
    the read resolve to one real memory location, so the solver only
    reports genuine data-dependent branching, not addressing noise.
    """
    state = proj.factory.blank_state(addr=block_addr)
    if loc.kind == "stack" and loc.base_reg_offset is not None:
        # arbitrary but fixed and well clear of any real memory angr
        # would otherwise allocate, so it can't collide with anything
        state.registers.store(loc.base_reg_offset, 0x7f0000001000)

    simgr = proj.factory.simgr(state)
    simgr.step()  # execute exactly this block

    values = set()
    for st in simgr.active + simgr.deadended:
        try:
            expr = _read_state_value(st, loc)
            if expr is None:
                log.warning(
                    "Block 0x%x: stack location unresolved, cannot read state "
                    "var symbolically -- see extract_state_location warning",
                    block_addr,
                )
                continue
            sols = st.solver.eval_upto(expr, MAX_SYMBOLIC_SOLUTIONS)
            values.update(sols)
        except claripy.errors.ClaripyError as e:
            log.warning("Solver error on block 0x%x: %s", block_addr, e)

    if len(values) >= MAX_SYMBOLIC_SOLUTIONS:
        log.warning(
            "Block 0x%x hit solution cap (%d) -- state var or slicing is "
            "probably wrong, treat this result with suspicion",
            block_addr, MAX_SYMBOLIC_SOLUTIONS,
        )

    return values


def _check_state_write(proj, block_addr: int, loc: StateLocation):
    """
    Tri-state version of the write-detection logic in
    _try_constant_fastpath: distinguishes "no write to the state
    location happened in this block" from "a write happened but its
    value isn't a compile-time constant" -- the propagation in
    resolve_case_chain_static needs this distinction, since the first
    case means "carry the previously known value forward" and the
    second means "the previously known value is no longer valid".

    Returns ("constant", value), ("non_constant", None), or ("none", None).
    """
    irsb = proj.factory.block(block_addr).vex
    tmp_defs = {}
    result = ("none", None)

    for stmt in irsb.statements:
        if isinstance(stmt, pyvex.IRStmt.WrTmp):
            tmp_defs[stmt.tmp] = stmt.data

        wrote_here = False
        val = None
        if loc.kind == "reg" and isinstance(stmt, pyvex.IRStmt.Put):
            if stmt.offset == loc.reg_offset:
                wrote_here = True
                val = _resolve_const(stmt.data, tmp_defs)

        if loc.kind == "stack" and loc.stack_delta is not None and \
                isinstance(stmt, pyvex.IRStmt.Store):
            store_base, store_delta = _extract_stack_delta(stmt.addr, tmp_defs, proj.arch)
            if store_base == loc.base_reg_offset and store_delta == loc.stack_delta:
                wrote_here = True
                val = _resolve_const(stmt.data, tmp_defs)

        if wrote_here:
            result = ("constant", val) if val is not None else ("non_constant", None)

    return result


def resolve_case_chain_static(proj, entry_addr: int, chain_addrs: set, real_blocks: set,
                               full_graph, loc: StateLocation, max_depth: int = 12) -> dict:
    """
    Statically propagate the state variable's constant value forward
    through a case's branch chain, from its true entry point, without
    executing anything.

    Confirmed necessary against real batch results: a case's state
    assignment can occur in an earlier block of its branch chain than
    the terminal block being analyzed (e.g. the case entry sets a
    register to a literal, an unconditional child block does unrelated
    work and never touches that register again before exiting) --
    per-block-in-isolation analysis cannot see that earlier assignment.
    This carries a known constant value forward across blocks the same
    way a compiler's constant-propagation pass would, entirely at the
    IR level with no solver or execution involved, avoiding the
    active/deadended state-tracking bug class that broke the previous,
    reverted, full symbolic whole-chain attempt (commit history: that
    attempt used live simulation stepping; this one never executes
    anything, so that bug class cannot recur here).

    Returns {terminal_block_addr: set(values)} for every path where a
    constant was successfully determined. Paths where no constant can
    be pinned down statically are simply absent from the result --
    the caller falls back to per-block symbolic analysis for those.
    """
    results = {}
    stack = [(entry_addr, None, frozenset(), 0)]

    while stack:
        block_addr, known_value, visited, depth = stack.pop()
        if block_addr in visited or depth > max_depth or block_addr in chain_addrs:
            continue
        visited = visited | {block_addr}

        write_kind, write_val = _check_state_write(proj, block_addr, loc)
        if write_kind == "constant":
            known_value = write_val
        elif write_kind == "non_constant":
            known_value = None

        succs = set(full_graph.successors(block_addr)) if block_addr in full_graph else set()
        if succs and succs.issubset(chain_addrs):
            if known_value is not None:
                # Apply value_offset here too, for the same reason as in
                # analyze_block: a literal value stored at loc's location
                # is not necessarily what the dispatcher actually indexes
                # with. Default value_offset=0 is a no-op for every
                # function without this arithmetic-transform pattern.
                results.setdefault(block_addr, set()).add(known_value + loc.value_offset)
            continue

        for succ in succs:
            if succ in real_blocks:
                stack.append((succ, known_value, visited, depth + 1))

    return results
