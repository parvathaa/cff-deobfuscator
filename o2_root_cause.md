# -O2 Root Cause Investigation

Follows up on the earlier finding (Section 3.11 / o2_results.csv) that widening
resolve_switch_block's search depth did not fix -O2 detection. This investigation
identifies the actual root cause via direct IR inspection.

## Method

Picked two -O2 CFF-obfuscated zlib functions of different sizes (gzdirect, 7
blocks; inflateInit2_, 15 blocks), dumped their raw VEX IR at the function entry
and at the top in-degree-outlier candidate, and compared obfuscated vs plain
block counts for both.

## Finding 1: No dedicated frame pointer

Confirmed directly: neither function's prologue sets up rbp as a frame pointer
(no "push rbp; mov rbp, rsp" pattern). GCC omits the frame pointer by default
starting at -O1, so all stack-relative addressing in these binaries must be
tracked against a moving stack pointer, not the fixed base register our
stack-addressing logic (Section 2.7) assumes.

## Finding 2: The in-degree "dispatcher candidate" is a shared function epilogue

For BOTH functions tested, the only structural in-degree outlier found by
detect_dispatcher's z-score check was not a CFF dispatcher at all -- it was a
compiler-generated shared epilogue block (multiple exit paths converging on
one shared "restore callee-saved registers; ret" sequence). This is a
completely ordinary -O2 optimization (avoiding duplicated epilogue code at
every return site), unrelated to CFF, that happens to produce the exact same
graph signature (high in-degree convergence point) our heuristic looks for.

Confirmed via raw IR: block 0x40cbda (gzdirect) pops rbx and returns
(Ijk_Ret). Block 0x40c860 (inflateInit2_) pops rbx, rbp, r12, r13 in sequence
and returns. Neither matches either recognized switch pattern (Section 2.6),
and our detection redesign (Section 3.8) correctly rejects both -- this is
exactly the "no switch-signature block found" warning seen throughout every
-O2 test run.

Critically, in both functions, this shared epilogue was the ONLY z-score
candidate found. There was no second, real dispatcher-shaped node anywhere
in either function to fall back to.

## Finding 3: Flattening does not survive -O2 compilation (decisive)

Compared obfuscated vs plain block counts directly:

| Function | Obfuscated blocks | Plain blocks | Ratio |
|---|---|---|---|
| gzdirect | 7 | 7 | 1.00x |
| inflateInit2_ | 15 | 17 | 0.88x |

At -O0, obfuscated binaries consistently have 2-3x MORE blocks than plain
(flattening machinery is untouched by the compiler). At -O2, these two
functions show the OPPOSITE: gzdirect has identical block count to its plain
counterpart, and inflateInit2_'s obfuscated version is actually SMALLER than
plain. This is strong, direct evidence that GCC's -O2 optimizer substantially
or completely undoes Tigress's control-flow flattening as a side effect of
ordinary optimization (control-flow simplification, jump threading, dead-block
elimination) -- independent of anything this pipeline does or doesn't do.

## Reframed conclusion

The -O2 "boundary" documented in Section 3.11 is not primarily a limitation of
this pipeline's detection or extraction logic. The more fundamental finding is
that CFF obfuscation combined with aggressive compiler optimization is
inherently fragile: for at least the two functions directly inspected here,
there is little to no flattening structure left in the compiled binary for
ANY detection approach to find. The frame-pointer-omission issue (Finding 1)
remains a real, separate limitation that would still need addressing for any
function where flattening does survive -O2 intact, but it is not the primary
explanation for the sharp recall collapse observed in Section 3.11.

## Scope and honest limits of this finding

This was checked directly on two functions, not the full -O2 batch. A
systematic follow-up (comparing obfuscated-vs-plain block-count ratios across
all -O2 pure-CFF targets, not just two) would be needed to state confidently
what fraction of functions lose their flattening structure entirely versus
retain it in some altered form. This is flagged as a natural, well-scoped
next step rather than claimed as exhaustively confirmed here.
