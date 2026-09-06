import logging
logging.disable(logging.CRITICAL)  # must run BEFORE importing angr to suppress the unicorn-load warning
import angr, json, time

from cff_deobfuscator import dispatcher, cfg_recovery

print("=" * 60)
print("RAVEL DEMO: Full batch (zlib, Tigress CFF, 50%, -O0)")
print("=" * 60)
print()

obf_path = "dataset/zlib/obfuscated/tigress/CFF/50/zlib_tigress_gcc_x64_CFF_50_1_O0.exe"
obf_json_path = "dataset/zlib/obfuscated/tigress/CFF/50/zlib_tigress_gcc_x64_CFF_50_1_O0.json"

print("[*] Loading and analyzing obfuscated binary...")
proj = angr.Project(obf_path, auto_load_libs=False)
cfg = proj.analyses.CFGFast(normalize=True, data_references=False, force_complete_scan=False)
base = proj.loader.main_object.mapped_base
print("[+] Ready.")
print()

entries = json.load(open(obf_json_path))
targets = [e for e in entries if e.get("obfu") == ["cff"]]
print(f"[*] {len(targets)} pure-CFF functions to process\n")

detected = 0
compared = 0
within_2 = 0

for i, entry in enumerate(targets, 1):
    name = entry["name"]
    addr = int(entry["address"], 16) if isinstance(entry["address"], str) else entry["address"]
    func = cfg.kb.functions.function(addr=addr + base)
    if func is None:
        continue
    try:
        result = cfg_recovery.recover_function_cfg(proj, func)
    except Exception:
        result = None

    status = "MISS"
    if result and result.dispatcher_addr is not None:
        detected += 1
        if result.stats.get("error") is None and result.recovered_cfg.number_of_nodes() > 0:
            compared += 1
            status = "OK"
        else:
            status = "EXTRACT-FAIL"
    print(f"  [{i:>2}/{len(targets)}] {name:<28} {status}")
    time.sleep(0.08)  # small pacing delay so the live tally is visible on screen

print()
print("=" * 60)
print(f"  Detection recall: {detected}/{len(targets)} ({100*detected/len(targets):.0f}%)")
print("=" * 60)
