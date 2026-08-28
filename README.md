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
   in-degree outlier + back-edge-funneling structural signature.
   Obfuscator-agnostic (should work on both Tigress and OLLVM CFF, since
   both produce the same shape), but only tested in design against
   Tigress so far.

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

4. **`evaluate.py`** — since the dataset ships the *plain* binary for
   every obfuscated function, ground truth isn't hand-labeled: we
   recover the plain function's CFG the normal way (no dispatcher games
   needed) and diff against it. Reports node recall + edge
   precision/recall/F1 under a topology-order node alignment.

## Batch validation results (zlib, Tigress CFF/50, -O0)

Ran the full pipeline against all 69 pure-CFF functions in a single
obfuscated zlib binary (`zlib_tigress_gcc_x64_CFF_50_1_O0.exe`),
comparing recovered cyclomatic complexity (`edges - nodes + 2`) against
each function's plain (unobfuscated) counterpart. Cyclomatic complexity
is used here rather than exact node/edge matching because the plain and
obfuscated binaries are separate compilations -- block splitting can
differ even when the underlying logic is identical, so exact structural
match was never the right bar. Complexity captures branching structure
while being insensitive to how blocks happen to be split.

- **39/69** functions: no dispatcher detected (structural detection
  heuristic missed them, or they were small enough that Tigress's
  flattening didn't produce a clear in-degree outlier -- not yet
  root-caused, a good next investigation)
- **30/69** functions: dispatcher found, recovery attempted, ground
  truth available for comparison
  - **1/30** exact cyclomatic-complexity match
  - **22/30** within ±2 of ground truth
  - Worst outliers: `init_block` (+13), `deflate`/`inflateBack` (+8),
    `deflate_stored` (+6) -- see below, these all share one root cause

`send_tree` itself (the function used for initial validation, jump-table
dispatcher, 61 cases, `rbp`-relative state): recovered complexity 19 vs
ground truth 20.

## Known gap: register-based state variables in branching case chains

**Root cause, confirmed via direct diagnostic (not guessed):** for
functions where the dispatcher state variable lives in a **register**
(e.g. `rax`) rather than on the stack, and the actual state assignment
happens in an **earlier block within a case's branch chain** rather
than in the terminal block that jumps back to the dispatcher, the
pipeline currently produces wrong results.

Concretely, for `init_block` (diff +13, the worst outlier): the state
location is `StateLocation(kind='reg', reg_offset=16)` (rax). Direct
inspection of all 13 terminal blocks in its case chains showed every
one of them reading `rax` as still-symbolic/unconstrained at that
point -- meaning none of them write to `rax` themselves. The real
assignment happens in an earlier block in the same case's branch chain,
which the current single-block-in-isolation analysis (`analyze_block`
in `state_analysis.py`, called once per terminal block via a fresh
`blank_state`) never sees, since `blank_state` starts fresh at each
block address and has no memory of what happened earlier in the chain.
This is very likely why the "hit solution cap (32)" warnings correlate
almost exactly with the largest complexity-diff outliers in the batch
results above: an unconstrained register produces arbitrary-looking
wide solution sets that have nothing to do with the code's actual logic.

**What was tried and explicitly reverted (documented for the record,
not swept under the rug):** an attempt was made to fix this by
symbolically executing each case's *entire* branch chain from its true
entry point (via a new `resolve_case_chain` function) rather than each
terminal block in isolation, tracking path history to attribute
resolved values back to the correct terminal block. This was reverted
after testing showed it made results dramatically worse (`send_tree`
went from -1 off to -41 off) and every single case failed to resolve
("never reached the dispatcher chain"). The bug was very likely in how
active/deadended states were tracked across the `simgr.step()` loop
(only `simgr.active` was checked for chain-arrival, dropping states
that angr moves into `.deadended` -- the working single-block version
correctly checked `active + deadended` together, and this distinction
was lost in the rewrite), combined with `max_depth=8` allowing branch
explosion with no pruning, which also explains the severe slowdown
observed. The working commit (`00cf211`, current `HEAD` as of this
writing) predates this attempt and remains the validated baseline.

**Next attempt should be narrower**, not a full path-exploration
rewrite: e.g. extend `_try_constant_fastpath`'s static IR scan
backward through a *linear* (non-branching) predecessor chain first,
before reaching for full symbolic execution, and fix the
active/deadended state-tracking bug explicitly if a symbolic
whole-chain approach is attempted again.

## Other known gaps

- **Exit-chain (if/elif) dispatchers less tested than jump-table ones.**
  Both `build_case_map()` paths are implemented (`_build_case_map_exit_chain`
  and `_build_case_map_jumptable`), but all real validation so far (the
  batch results above) happened to be against jump-table dispatchers,
  since that's what this Tigress/-O0/zlib combination produces. The
  exit-chain path is implemented from the same IR patterns but hasn't
  been exercised against a real exit-chain sample yet.
- **Stack-slot resolution assumes -O0 simplicity.** `_extract_stack_delta`
  expects `Add(Get(sp/bp), Const)` directly. `-O2` frame-pointer
  elimination or spill-slot reuse will break this — start all testing
  at `-O0` per the plan, then harden once -O0 numbers look right.
- **No inter-procedural handling.** Dataset also has `copy`/`merge`/`split`
  passes; v1 only targets intra-procedural CFF.
- **`MAX_SYMBOLIC_SOLUTIONS` cap (32)** is a blunt safety valve, not a
  principled bound — if you see functions hitting it, that's diagnostic
  signal the state variable was misidentified, not that the function is
  legitimately that branchy (see the register-based-state gap above,
  which is the confirmed cause in every case checked so far).
- **39/69 pure-CFF functions in the batch test had no dispatcher
  detected at all** — not yet root-caused. Worth checking whether these
  are small functions where Tigress's flattening didn't produce a clear
  in-degree statistical outlier (`INDEGREE_ZSCORE_THRESHOLD` in
  `dispatcher.py` may need loosening), or a genuinely different
  dispatcher shape not yet seen.

## Roadmap toward the actual end goal (hybrid analysis)

The reason for building the symbolic fallback carefully now is that it's
the piece the hybrid design leans on later. Rough shape of the next
iterations:

- **Iteration 2**: fix the register-based-state / branch-chain gap
  documented above (properly this time — narrower approach, fix the
  active/deadended tracking bug), root-cause the 39/69 no-dispatcher-
  detected functions, extend validation to exit-chain dispatchers and
  `-O2` binaries, and run batch validation across obfuscation levels
  (10%/50%/100%) for a per-level accuracy curve — a natural chapter
  figure.
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

Validated against real Tigress-flattened zlib binaries from the
quarkslab dataset (see Batch validation results above) — this is no
longer "not yet tested against real binaries." The core recovery
pipeline (dispatcher detection, jump-table case-map reading,
branch-aware real-block discovery, constant-propagation state
resolution) works correctly on the common case. The remaining gap is
specifically register-based state variables assigned earlier in a
branch chain than the terminal block (documented above), plus the
untested paths noted in "Other known gaps."
