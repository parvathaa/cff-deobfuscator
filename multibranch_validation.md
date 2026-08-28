# Multi-Branch Case Validation

Confirms the real-block discovery algorithm (`discover_real_blocks`) correctly
handles cases with more than a simple 2-way branch, not just the single
if/else pattern used in earlier examples.

## Method

Scanned all 30 successfully-detected pure-CFF functions in
zlib_tigress_gcc_x64_CFF_50_1_O0.exe. For every case entry, walked forward
through the case's own real-block chain and measured (a) total block count
and (b) how many blocks have 2+ successors still within the same chain
(a genuine branch point, not just a longer straight-line sequence).

## Result

642 cases across the batch have 3 or more real blocks in a single case chain.
The largest, gz_open's case at entry 0x408362, has 16 total blocks.

Direct inspection of that case confirmed it is genuine branching, not a long
straight line:
- 0x408362: 2 successors (initial branch)
- 0x408378: 13 successors -- a genuine 13-way branch, each leading to a
  distinct small handler block
- All 13 handler blocks converge to the same exit block (0x40841b) before
  returning to the dispatcher

gz_open parses fopen-style mode strings ("rb", "wb9", "a+", etc.), so this
is very plausibly the compiled form of a character-by-character comparison
sequence -- exactly the "branching buried inside one flattened case" pattern
the real-block discovery algorithm was designed, but not previously directly
confirmed, to handle correctly.

## Conclusion

The forward-traversal design (walk from a case's entry point through every
successor until reaching the dispatcher, with no assumption about how many
branches exist) is confirmed against a real 13-way branch, not just the
2-way if/else example used elsewhere in this project. This closes the open
question of whether multi-branch handling was only theoretically correct.
