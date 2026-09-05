"""
loader.py

Handles loading a target binary with angr and isolating the function(s)
we want to deobfuscate, using the dataset's ground-truth JSON to resolve
addresses/names for stripped binaries.

Dataset ground truth format (per quarkslab/diffing_obfuscation_dataset):
    [
      {"name": "inflate_fast", "address": "0x4013a0", "obfuscated": true},
      ...
    ]
"""

import json
import logging
from dataclasses import dataclass
from pathlib import Path

import angr

log = logging.getLogger("cff.loader")


@dataclass
class TargetFunction:
    name: str
    address: int
    obfuscated: bool
    size: int | None = None
    obfu_passes: list[str] = None  # e.g. ["cff"], or ["cff", "encodearith"] for mix1/mix2


class BinaryContext:
    """
    Wraps an angr Project + its CFGFast recovery + ground-truth metadata
    for one binary in the dataset.
    """

    def __init__(self, binary_path: str, ground_truth_path: str | None = None,
                 auto_cfg: bool = True):
        self.binary_path = Path(binary_path)
        self.proj = angr.Project(str(self.binary_path), auto_load_libs=False)
        self.cfg = None
        self.functions: dict[str, TargetFunction] = {}

        if ground_truth_path:
            self._load_ground_truth(ground_truth_path)

        if auto_cfg:
            self.build_cfg()

    def _load_ground_truth(self, path: str):
        with open(path) as f:
            entries = json.load(f)
        # Confirmed against actual dataset output that ground-truth JSON
        # comes in two shapes depending on the project: zlib's plain/
        # obfuscated files and sqlite's obfuscated file are a list of
        # {"address", "name", "obfu"} dicts, but sqlite's *plain* file is
        # instead a flat {address_hex: name} map with no obfu info at all
        # (plain binaries were never obfuscated, so there's nothing to
        # record). Normalize both into the same iteration below.
        if isinstance(entries, dict):
            entries = [{"address": addr, "name": name, "obfu": []}
                       for addr, name in entries.items()]
        for e in entries:
            addr = e["address"]
            addr = int(addr, 16) if isinstance(addr, str) else addr
            # "obfu" is a list of applied obfuscation pass names, e.g.
            # ["cff"], or an empty list for un-obfuscated functions in
            # this file. A function counts as obfuscated if non-empty.
            obfu_passes = e.get("obfu", [])
            self.functions[e["name"]] = TargetFunction(
                name=e["name"],
                address=addr,
                obfuscated=bool(obfu_passes),
                obfu_passes=obfu_passes,
            )
        log.info("Loaded %d ground-truth function entries", len(self.functions))

    def build_cfg(self):
        """
        CFGFast is enough here: we don't need CFGEmulated's precision for
        dispatcher detection, and it's dramatically faster on realistic
        binaries like zlib/sqlite. We recover function boundaries and
        basic-block structure, which is all stage 1 needs.
        """
        log.info("Running CFGFast on %s", self.binary_path.name)
        self.cfg = self.proj.analyses.CFGFast(
            normalize=True,          # important: merges overlapping blocks cleanly
            data_references=False,   # skip; we don't need data xrefs for CFF
            force_complete_scan=False,
        )
        return self.cfg

    def get_obfuscated_targets(self) -> list[TargetFunction]:
        return [f for f in self.functions.values() if f.obfuscated]

    def get_angr_function(self, target: TargetFunction):
        """
        Resolve a TargetFunction to angr's knowledge-base Function object.

        Dataset ground-truth JSON addresses are file-relative virtual
        addresses (as compiled, pre-rebase) -- confirmed against actual
        dataset output where a PIE binary's mapped_base was 0x400000 and
        JSON addresses were small offsets like 0xe1c6 that only resolved
        to a real Function once shifted by mapped_base. For non-PIE
        binaries mapped_base is typically already baked into the
        addresses the linker chose, so mapped_base there should be the
        object's actual base (angr sets it correctly either way) --
        adding it is safe and a no-op if the object isn't relocated.
        """
        base = self.proj.loader.main_object.mapped_base
        candidates = [target.address, target.address + base]

        func = None
        for addr in candidates:
            func = self.cfg.kb.functions.function(addr=addr)
            if func is not None:
                break

        if func is None:
            # last resort: small forward scan from the rebased address,
            # in case of alignment/padding bytes before the real prologue
            for delta in range(0, 16):
                func = self.cfg.kb.functions.function(addr=target.address + base + delta)
                if func is not None:
                    log.warning("Function %s resolved with +%d byte offset",
                                target.name, delta)
                    break

        if func is None:
            log.error("Could not resolve function %s @ 0x%x (tried raw and "
                       "+0x%x rebased) in CFG",
                       target.name, target.address, base)
        return func
