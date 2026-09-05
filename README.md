# CFF Deobfuscator — v1

Structural CFF-dispatcher recovery for stripped x64 ELF binaries, built
against the [quarkslab diffing_obfuscation_dataset](https://github.com/quarkslab/diffing_obfuscation_dataset).

## Quick Start

### 1. Environment

Requires Python 3.10-3.12. **Python 3.13+ is not yet reliably supported**
by this project's dependencies (angr); if you're on a newer system Python,
use a virtual environment pinned to 3.12.

```bash
python3.12 -m venv angr-env
source angr-env/bin/activate
pip install -r requirements.txt
```

`angr` is a large, slow install (several minutes, many transitive
dependencies). This is expected.

### 2. Getting the dataset

This tool requires the Quarkslab `diffing_obfuscation_dataset` benchmark
binaries. The dataset's CLI is **not on PyPI** and must be installed
from source:

```bash
git clone https://github.com/quarkslab/diffing_obfuscation_dataset.git
cd diffing_obfuscation_dataset
pip install .
cd ..
```

Then download the specific binaries you want to test against, for example:

```bash
mkdir -p dataset
obfu-dataset-cli download-plain -r dataset/ -t 5 zlib
obfu-dataset-cli download-obfuscated -r dataset/ -t 5 -p zlib -o tigress -op CFF -l 50
```

(Note: `download-plain` takes the project name as a plain argument;
`download-obfuscated` requires it via `-p`. This asymmetry is in the
upstream tool, not this project.)

### 3. Running the pipeline

**Run from the outer project directory** (the parent of the
`cff_deobfuscator` package folder, *not* from inside it), otherwise
Python cannot resolve the package import:

```bash
cd path/to/cff_deobfuscator   # NOT cff_deobfuscator/cff_deobfuscator
python3 -m cff_deobfuscator.cli --help
```

If you've edited any source file and results seem stale or inconsistent,
clear the bytecode cache before re-running:

```bash
find . -name "__pycache__" -exec rm -rf {} +
```

---

## What Normal Output Looks Like

**This tool logs extensively by design, and most warnings you'll see
are expected, not errors.** In particular:

- `unicornlib.dylib` failed to load — harmless; only affects an optional
  acceleration backend not used by this pipeline.
- `Switch block looked like a jump table but pattern extraction failed`
  — expected for functions the detection heuristic flags as candidates
  but correctly rejects (often ordinary code containing a real C
  `switch` statement, not CFF). Detection is deliberately permissive;
  extraction acts as the correctness gate.
- `no switch-signature block found within N hops` — same as above, a
  candidate was tried and correctly rejected.

**A genuinely broken run** looks like a Python traceback / exception,
not a `WARNING` or `ERROR`-prefixed log line. If you see a real
traceback, that's a bug; the log lines above are not.

## What v1 does

1. **`dispatcher.py`** — detects the flattening dispatcher block via an
   in-degree outlier, confirmed by actually resolving a real switch
   structure (jump table or 3+-case comparison chain) downstream, rather
   than by graph statistics alone. An earlier version relied on a
   back-edge-funneling threshold instead; this was found, by direct
   comparison against real non-CFF functions, to be unreliable (several
   non-CFF functions scored higher on that metric than genuine CFF
   functions did), and was replaced. Detection recall improved from 43%
   to 86% as a result (an earlier measurement reported 93%, taken before
   a separate bug in `resolve_switch_block` -- since fixed -- was found
   to be inflating detection by misclassifying some return/call blocks
   as switches). Obfuscator-agnostic in principle (should work on
   both Tigress and OLLVM CFF, since both produce the same shape), but
   only validated against Tigress so far.

2. **`state_analysis.py`** — extracts the dispatcher's state variable
   location (register or stack slot) directly from IR, then resolves
   each real block's next-state value via:
   - **Tier 1 (fast)**: literal constant read straight off VEX IR — no
     solver, covers the common case.
   - **Tier 2 (fallback)**: symbolic execution + `solver.eval_upto()`
     when the next-state value is data-dependent — this is also how
     genuinely-branching real blocks (an if/else that survived inside a
     single flattened "case") get recovered as multiple edges instead of
     one.

3. **`cfg_recovery.py`** — reads the dispatcher's own case table
   (static, since the dispatcher itself isn't obfuscated) and stitches
   real-block → real-block edges together.

4. **Evaluation** — since the dataset ships the *plain* binary for every
   obfuscated function, ground truth isn't hand-labeled: we recover the
   plain function's CFG the normal way (no dispatcher games needed) and
   compare against it. `batch_eval.py` (used by the `regenerate_*_csv.py`
   scripts, and the source of every number in this README) compares
   recovered cyclomatic complexity against ground truth -- found to be
   the more robust metric, since exact node/edge alignment is unreliable
   across separate compilations of the same source (see "Batch
   validation results" below). `evaluate.py`/`cli.py` implement an
   earlier, different metric (node recall + edge precision/recall/F1
   under a topology-order alignment) that is **not** what any reported
   number in this repo currently uses -- kept for reference, not wired
   into the reproducible batch scripts.

## Batch validation results (zlib, Tigress CFF/50, -O0)

Reproducible via `python3 -m cff_deobfuscator.regenerate_intensity_csv`
(and the sibling `regenerate_o2_csv` / `regenerate_sqlite_csv` scripts)
-- these regenerate `batch_results_by_intensity.csv`, `o2_results.csv`,
and `sqlite_generalization_results.csv` from scratch via `batch_eval.py`,
so the numbers below are never hand-adjusted. Comparison is by recovered
cyclomatic complexity (`edges - nodes + 2`) against each function's plain
(unobfuscated) counterpart, not exact node/edge matching -- the plain and
obfuscated binaries are separate compilations, so block splitting can
differ even when the underlying logic is identical; complexity captures
branching structure while being insensitive to that.

Level 50, 69 pure-CFF functions:
- **10/69** functions: no dispatcher detected
- **1/69** functions: dispatcher found, but extraction correctly aborted
  with an explicit error (state-variable location extraction failed)
- **58/69** functions: dispatcher found, recovery attempted, ground
  truth available for comparison
  - **16/58** exact cyclomatic-complexity match
  - **50/58** within ±2 of ground truth
  - mean absolute diff: 1.48

`send_tree` itself (the function used for initial development, jump-table
dispatcher, 61 cases, `rbp`-relative state): recovered complexity 19 vs
ground truth 20.

Across the full obfuscation-intensity sweep (10%-100%), detection recall
is **not** flat -- it rises with intensity, from 78.6% at 10% to 91.2% at
100%, while within-2 accuracy stays roughly stable (73%-87%) throughout.
On sqlite (1,199 pure-CFF functions, 17x zlib, zero code changes):
77% detection recall, 86% within-2 accuracy, 31% exact match. On `-O2`
(zlib level 50): detection recall collapses to 11% (see the dedicated
gap below) -- root-caused, not just observed.

## Resolved: register-based state variables in branching case chains

**Was an open gap, now fixed.** For functions where the dispatcher state
variable lives in a register (e.g. `rax`) rather than on the stack, and
the actual state assignment happens in an earlier block within a case's
branch chain rather than the terminal block that jumps back to the
dispatcher, single-block-in-isolation analysis couldn't see the earlier
assignment.

**What was tried and explicitly reverted (kept here for the record):**
a first fix symbolically executed each case's *entire* branch chain from
its true entry point, tracking path history to attribute resolved values
back to the correct terminal block. This made results dramatically worse
(`send_tree` went from -1 off to -41 off) due to a state-tracking defect
(active/deadended simulation states weren't both checked across the
`simgr.step()` loop) combined with unbounded branch exploration. It was
reverted.

**What actually fixed it:** `resolve_case_chain_static` in
`state_analysis.py` -- static (no execution) constant propagation forward
across a case's branch chain at the IR level, carrying a known literal
value across blocks rather than re-executing anything. This sidesteps
the state-tracking bug class entirely, since nothing is symbolically
stepped. See `cfg_recovery.recover_function_cfg` for how this is tried
before falling back to the original per-block analysis.

## Resolved: dispatcher detection false negatives (was "39/69 not detected")

An earlier version of this README reported 39/69 functions with no
dispatcher detected at all, "not yet root-caused." That number describes
the *pre-redesign* baseline (back-edge-funneling heuristic, since
replaced -- see `dispatcher.py`'s module docstring). Under the current
switch-resolution-confirmed detection, the same batch misses only 10/69
(see numbers above), and each of those 10 has been individually traced:
either the state variable's initial in-degree candidate never resolves a
switch structure at all (a genuine open miss, not yet root-caused per
function), or -- confirmed for at least `gzopen64` -- the dispatcher
*is* found correctly but the bounds-check block supplying the jump
table's size sits on a control-flow path the BFS chain doesn't traverse,
so the case map comes back empty. That specific failure mode (dispatcher
found, case map empty) is a good next investigation, distinct from
"not detected at all."

## Resolved: `resolve_switch_block` misclassifying return/call blocks

The BFS in `resolve_switch_block` used to chase any constant jump target
without checking what kind of control transfer it was, so it could land
on a `ret` instruction (whose target -- the return address -- is also a
non-constant temp, which `_is_switch_block`'s old "non-constant next =
jump table" check misread as an indirect jump table) or wander into an
unrelated `call` target (once landing directly on `free@plt`). Fixed by
requiring `jumpkind == "Ijk_Boring"` before ever classifying a block as
a switch, and by only chasing a call edge when `proj.loader` confirms
it isn't an external call (no PLT stub, no symbol) -- a blanket call-ban
was tried first and broke a real case (`gzopen64`'s dispatcher sits
behind what angr's CFG labels a call to an internal, unnamed helper).

## `-O2`: root-caused, and worse than first reported

Corrected detection recall at `-O2` (zlib level 50) is **11%**, not the
30% originally reported -- most of that 30% was itself inflated by the
return/call misclassification bug above. Direct IR inspection shows the
in-degree candidate the heuristic finds at `-O2` is usually a
compiler-generated **shared epilogue** (multiple function-exit paths
converging on one register-restore-and-return sequence), which
coincidentally produces the same high-in-degree signature as a real
dispatcher. Block-count comparison against plain compilations confirms
this isn't a detection failure on structure that's still there: at `-O0`
obfuscated binaries have 2-3x more blocks than plain (flattening
machinery untouched); at `-O2`, two directly-inspected functions showed
ratios of 1.00 and 0.88 -- GCC's optimizer substantially or completely
undoes Tigress's flattening as a side effect of ordinary optimization.
See `o2_root_cause.md` for the full investigation. Checked on two
functions directly, not the full `-O2` batch -- a systematic
block-count comparison across all `-O2` targets is a natural next step.

## Resolved (as far as evidence allows): exit-chain (if/elif) dispatchers

Both `build_case_map()` paths are implemented
(`_build_case_map_exit_chain` and `_build_case_map_jumptable`), but
every real validation so far had happened to be against jump-table
dispatchers. Searched exhaustively for a real exit-chain sample to
validate against: the full zlib intensity sweep (10%-100%, jump-table
in every one of ~700 detected dispatchers) and all 1,199 pure-CFF
functions in sqlite. Three sqlite functions
(`sqlite3PcacheInitialize`, `sqlite3_bind_text16`, `jsonPathSyntaxError`)
initially appeared to be exit-chain dispatchers with 0 extractable
cases each -- direct IR inspection showed this was a real, separate
bug: `_is_switch_block`'s `exit_count >= 2` check counted *any* Exit
statement, including `Ijk_SigSEGV` exits (VEX's semantic modeling of
the CPU's alignment-fault behavior for aligned SSE stores, e.g.
`movaps` in a variadic function's `va_start` register-save-area
prologue -- `jsonPathSyntaxError` is a variadic error formatter). Fixed
by requiring `jumpkind == "Ijk_Boring"` in both this check and
`_build_case_map_exit_chain`'s own Exit-statement filter. After the
fix, none of the three candidates classify as exit-chain any more (one
now correctly resolves to a real jump-table dispatcher further down
the chain; the others no longer detect at all). Re-scanning both
codebases after the fix: **zero exit-chain dispatchers found anywhere**
-- Tigress's `-O0` flatten pass appears to exclusively emit jump
tables, at least across every sample in both tested codebases. The
exit-chain code path remains implemented and untested against a real
sample, but this is now an evidenced statement about what Tigress
actually produces, not an unexamined assumption -- validating it
would require either a different obfuscator/dataset, or hand-crafting
a Tigress input specifically structured to force that code path.
- **Stack-slot resolution assumes -O0 simplicity.** `_extract_stack_delta`
  expects `Add(Get(sp/bp), Const)` directly. `-O2` frame-pointer
  elimination or spill-slot reuse will break this — start all testing
  at `-O0` per the plan, then harden once -O0 numbers look right.
- **No inter-procedural handling.** Dataset also has `copy`/`merge`/`split`
  passes; v1 only targets intra-procedural CFF.
- **`MAX_SYMBOLIC_SOLUTIONS` cap (32)** is a blunt safety valve, not a
  principled bound — if you see functions hitting it, that's diagnostic
  signal the state variable was misidentified, not that the function is
  legitimately that branchy.
- **Dispatcher found but case map empty** (confirmed for `gzopen64`,
  see "Resolved: dispatcher detection false negatives" above) -- worth
  checking whether other misses share this same cause.

## Roadmap toward the actual end goal (hybrid analysis)

The reason for building the symbolic fallback carefully now is that it's
the piece the hybrid design leans on later. Rough shape of the next
iterations:

- **Iteration 2 (mostly done)**: the register-based-state / branch-chain
  gap is fixed (see "Resolved" sections above), detection false
  negatives dropped from 39/69 to 10/69 and the remaining ones are
  partially root-caused, `-O2` has been investigated and its collapse
  explained, and batch validation now runs across the full 10%-100%
  intensity sweep (see `batch_results_by_intensity.csv`, reproducible
  via `regenerate_intensity_csv.py`). Still open: exit-chain dispatcher
  validation (see "Other known gaps").
- **Iteration 3 (hybrid)**: pure static symbolic execution hits the
  classic **path explosion / code coverage ceiling** — deeply nested or
  loop-heavy real blocks won't get fully explored by Tier 2 alone within
  reasonable time, and some next-state values genuinely depend on
  runtime input (network buffers in zlib, file content in sqlite) that
  static analysis can't concretize meaningfully. Plan: add a **dynamic
  tracing pass** — instrument actual runs of the target binary (e.g. via
  angr's concrete/tracer mode, or DynamoRIO/Triton for lighter-weight
  tracing) with representative inputs, and *merge* observed dispatcher
  edges into the recovered CFG. This is where the dissertation's
  static-vs-dynamic-vs-hybrid comparison chapter comes from directly:
  you'll have real numbers on (a) static-only coverage, (b) dynamic-only
  coverage (bounded by how representative your input corpus is), and (c)
  hybrid coverage, per obfuscation level.

## Testing status

Validated against real Tigress-flattened zlib and sqlite binaries from
the quarkslab dataset, across the full obfuscation-intensity range and
both `-O0` and `-O2` (see "Batch validation results" above). The core
recovery pipeline (dispatcher detection, jump-table case-map reading,
branch-aware real-block discovery, two-tier state resolution) works
correctly on the common case and generalizes to a second, structurally
unrelated, 17x-larger codebase with zero code changes. All reported
numbers are reproducible from committed code via `batch_eval.py` and
the `regenerate_*_csv.py` scripts, not hand-run or ad hoc. The remaining
gaps are the exit-chain dispatcher path (implemented, never exercised
against a real sample) and the specific per-function causes behind the
small number of functions where a dispatcher is found but detection or
case-map extraction still doesn't produce a usable result (see "Other
known gaps").
