#!/usr/bin/env python3
# Symbolize OVMF crash addresses from an edk2-debug.log.
# Uses the "Loading driver at" lines to build a module load map,
# then addr2line on the per-module .dll files.
#
# Usage: python3 symbolize.py <debug.log> [build_dir]

import os, re, subprocess, sys

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <debug.log> [build_dir]", file=sys.stderr)
        sys.exit(1)
    log_path = sys.argv[1]
    build_dir = sys.argv[2] if len(sys.argv) > 2 else \
        "/home/gl055/research/projects/edk2-syzkaller/Build/OvmfX64/NOOPT_GCC5"

    # Parse module load map
    modules = []  # (base, name, entry)
    with open(log_path, "rb") as f:
        for line in f:
            line = line.decode("ascii", errors="ignore")
            m = re.search(r"Loading driver at (0x[0-9A-Fa-f]+)\s+EntryPoint=(0x[0-9A-Fa-f]+)\s+(\S+)", line)
            if m:
                modules.append((int(m.group(1), 16), m.group(3), int(m.group(2), 16)))
    modules.sort()

    # Find all PCs to symbolize
    pcs = set()
    with open(log_path, "rb") as f:
        for line in f:
            line = line.decode("ascii", errors="ignore")
            # ASan: "at pc 0x..."
            for m in re.finditer(r"at pc (0x[0-9A-Fa-f]+)", line):
                pcs.add(int(m.group(1), 16))
            # ASSERT: look for return addresses
            for m in re.finditer(r"Return IP address is (0x[0-9A-Fa-f]+)", line):
                pcs.add(int(m.group(1), 16))

    if not pcs:
        print("No PCs found to symbolize.")
        return

    # Find .dll files in build dir
    dll_map = {}  # module_name -> dll_path
    for root, dirs, files in os.walk(os.path.join(build_dir, "X64")):
        for f in files:
            if f.endswith(".dll") and "DEBUG" in root:
                name = f.replace(".dll", ".efi")
                dll_map[name] = os.path.join(root, f)

    # Symbolize each PC
    print(f"{'PC':<20} {'Module':<30} {'Offset':<12} {'Function / File:Line'}")
    print("-" * 90)
    for pc in sorted(pcs):
        mod_name = "?"
        mod_base = 0
        for base, name, entry in reversed(modules):
            if base <= pc:
                mod_name = name
                mod_base = base
                break
        offset = pc - mod_base
        sym = "?"
        dll = dll_map.get(mod_name)
        if dll:
            try:
                out = subprocess.check_output(
                    ["addr2line", "-e", dll, "-f", "-C", hex(offset)],
                    stderr=subprocess.DEVNULL, timeout=5
                ).decode().strip()
                lines = out.split("\n")
                func = lines[0] if lines else "?"
                fileline = lines[1] if len(lines) > 1 else "?"
                if func != "??" and fileline != "??:0":
                    sym = f"{func} at {fileline}"
                else:
                    sym = f"(no debug info at offset 0x{offset:x})"
            except:
                sym = f"(addr2line failed)"
        else:
            sym = f"(no .dll found for {mod_name})"
        print(f"0x{pc:016x} {mod_name:<30} 0x{offset:<10x} {sym}")

if __name__ == "__main__":
    main()
