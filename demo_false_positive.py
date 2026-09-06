import logging
logging.disable(logging.CRITICAL)  # must run BEFORE importing angr to suppress the unicorn-load warning
import angr, json, time

logging.disable(logging.NOTSET)  # re-enable normal logging for THIS demo -- we want to see it
logging.basicConfig(level=logging.INFO, format='%(levelname)-8s | %(message)s')

from cff_deobfuscator import dispatcher, cfg_recovery

print("=" * 60)
print("RAVEL DEMO: honest failure -- a non-CFF function")
print("=" * 60)
print()

obf_path = "dataset/zlib/obfuscated/tigress/CFF/50/zlib_tigress_gcc_x64_CFF_50_1_O0.exe"
obf_json_path = "dataset/zlib/obfuscated/tigress/CFF/50/zlib_tigress_gcc_x64_CFF_50_1_O0.json"

proj = angr.Project(obf_path, auto_load_libs=False)
cfg = proj.analyses.CFGFast(normalize=True, data_references=False, force_complete_scan=False)
base = proj.loader.main_object.mapped_base

entries = json.load(open(obf_json_path))
entry = next(e for e in entries if e["name"] == "inflate")
assert entry["obfu"] == [], "ground truth says this function WAS obfuscated -- pick a different target"
addr = int(entry["address"], 16) + base
func = cfg.kb.functions.function(addr=addr)

print(f"[*] Target: inflate @ {hex(addr)}")
print("[*] zlib's inflate() contains a genuine `switch (state->mode)` in the")
print("    ORIGINAL source (its own decompression state machine) -- ground")
print("    truth confirms Tigress never touched this function (obfu: []).")
print()
time.sleep(1.5)

print("[*] Step 1: Detection")
print("-" * 60)
disp_info = dispatcher.detect_dispatcher(func, proj=proj)
time.sleep(0.5)
if disp_info:
    print(f"\n[!] Detection FLAGGED this as a dispatcher candidate @ {hex(disp_info.dispatcher_addr)}")
    print("    A real switch statement structurally resembles a CFF")
    print("    dispatcher -- this is an expected, honest false positive.")
print()
time.sleep(1.5)

print("[*] Step 2: Extraction (the correctness gate)")
print("-" * 60)
result = cfg_recovery.recover_function_cfg(proj, func) if disp_info else None
time.sleep(0.5)
print()

print("=" * 60)
if disp_info is None:
    print("  RESULT: Not detected as a CFF candidate at all")
    print("  -> No incorrect graph was produced.")
elif result.stats.get("error") is not None:
    print("  RESULT: Extraction FAILED cleanly")
    print(f"  Reason: {result.stats.get('error')}")
    print("  -> No incorrect graph was produced.")
elif not result.stats.get("real_block_count"):
    # recover_function_cfg always adds the function's own entry address as
    # a node regardless of outcome, so recovered_cfg.number_of_nodes() is
    # never 0 even when zero real blocks were resolved -- real_block_count
    # is the reliable signal for a genuinely empty/degenerate recovery.
    print("  RESULT: Extraction produced an empty graph (degenerate, not wrong)")
    print(f"  Stats: {result.stats}")
    print("  -> No incorrect graph was produced.")
else:
    print("  RESULT: Extraction succeeded")
    print(f"  Stats: {result.stats}")
print("=" * 60)
