# EDK2 (UEFI firmware) support

Syzkaller supports fuzzing UEFI firmware built with the
[EDK2](https://github.com/tianocore/edk2) toolkit. The target firmware runs
inside QEMU/KVM as an OvmfPkgX64 image, and the syzkaller executor runs on the
Linux host in HostFuzzer mode. Communication between the executor and the
in-firmware agent (`SyzAgentDxe`) happens through a shared-memory region backed
by QEMU's `ivshmem-plain` device.

## Architecture overview

```
  Linux host                          QEMU guest (OVMF firmware)
 +-----------------+                 +---------------------------+
 | syz-manager     |                 | DXE drivers               |
 |   |             |                 |   |                       |
 |   v             |   ivshmem       |   v                       |
 | syz-executor <--|---- 256 MiB --->| SyzAgentDxe               |
 |   (HostFuzzer)  |   shared mem    |   dispatch loop           |
 +-----------------+                 +---------------------------+
```

The executor writes a serialized program into the ivshmem region, bumps a
doorbell word, and waits for the agent to ack. The agent walks the program's
call records and dispatches each one to the corresponding UEFI Boot Service,
Runtime Service, or protocol method. Coverage PCs are collected via
`-fsanitize-coverage=trace-pc` and written to a ring buffer in the same
ivshmem region.

## Prerequisites

- Linux host with KVM support (`/dev/kvm`)
- QEMU with `ivshmem-plain` support (stock `qemu-system-x86_64` works)
- GCC cross-compiler for EDK2 (the `GCC5` toolchain)
- The [cglosner/edk2](https://github.com/cglosner/edk2) fork with
  `SyzAgentDxe` and `SyzCoverLib` (branch `syzkaller-edk2`)

## Building EDK2

Clone the EDK2 fork and build OVMF with the syzkaller agent enabled:

```bash
export EDK2_DIR=/path/to/edk2-syzkaller

git clone https://github.com/cglosner/edk2.git "$EDK2_DIR"
cd "$EDK2_DIR"
git checkout syzkaller-edk2
git submodule update --init --recursive

make -C BaseTools -j$(nproc)
source edksetup.sh

build -p OvmfPkg/OvmfPkgX64.dsc -a X64 -t GCC5 -b NOOPT \
    -D SYZ_AGENT_ENABLE=TRUE \
    -D ASAN_ENABLE=TRUE \
    -n $(nproc)
```

The build output is in `Build/OvmfX64/NOOPT_GCC5/FV/`:
- `OVMF_CODE.fd` - firmware code (read-only pflash)
- `OVMF_VARS.fd` - variable store template (copied per-VM)

### Recommended: full sanitizer build

Build OVMF with every sanitizer enabled:

```bash
build -p OvmfPkg/OvmfPkgX64.dsc -a X64 -t GCC5 -b NOOPT \
    -D SYZ_AGENT_ENABLE=TRUE \
    -D ASAN_ENABLE=TRUE \
    -D ASAN_INSTRUMENT=TRUE \
    -D UBSAN_INSTRUMENT=TRUE \
    -D FD_SIZE_IN_KB=8192 \
    -n $(nproc)
```

Coverage:

- **ASan** (`-fsanitize=kernel-address --param asan-stack=1 --param asan-globals=1`)
  on every `DXE_DRIVER`, `UEFI_DRIVER`, `DXE_RUNTIME_DRIVER`,
  `UEFI_APPLICATION`, `DXE_CORE`, and `DXE_SMM_DRIVER` (99 of 110 DXE
  modules). Detects heap/stack/global OOB and use-after-free. Shadow
  lives in reserved DRAM at `0x30000000` (256 MB covering the low 2 GB).
- **UBSan** (`-fsanitize=undefined -fsanitize=pointer-overflow
  -fno-sanitize=alignment`) on the same module set. Detects signed
  integer overflow, shift out-of-bounds, array bounds, pointer
  overflow.
- **MMIOConstraintSan** (always on when `SYZ_AGENT_ENABLE=TRUE`).
  Validates every `cpu_io_mem_*` syscall target address against
  declared GCD MMIO regions.
- **ProtocolLifetimeSan** (always on). Hooks `UninstallProtocolInterface`
  and poisons interface memory so subsequent uses fire ASan UAF.
- **SMIBVS** (inert unless `-D SMM_REQUIRE=TRUE`). SMI CommBuffer
  validator — rejects pointers into SMRAM.

See `MdeModulePkg/Library/AsanLib/README.md` in the edk2 tree for the
firmware-side design details.

### Disabling a sanitizer for a single run

```bash
# ASan off, UBSan on
build ... -D ASAN_INSTRUMENT=FALSE -D UBSAN_INSTRUMENT=TRUE

# All off (production-style build with SyzAgent only)
build ... -D ASAN_INSTRUMENT=FALSE -D UBSAN_INSTRUMENT=FALSE
```

### Carveouts

`PciBusDxe` and `PciHostBridgeDxe` are explicitly opted out of ASan
per-component in `OvmfPkg/OvmfPkgX64.dsc`. PCI enumeration is
O(devices × MMIO-ops) and ASan-instrumenting it stalls TCG boot for
minutes. Target drivers (Fat, Ip4Dxe, Tcp4Dxe, etc.) remain fully
instrumented.

## Building syzkaller

```bash
export SYZ_DIR=/path/to/syzkaller
cd "$SYZ_DIR"

# Build the manager (runs inside syz-env Docker container)
CI=true ./tools/syz-env make manager

# Build the executor NATIVELY (not via syz-env) to avoid glibc mismatch.
# The executor runs on the host, not in Docker.
GIT_REV=$(git rev-parse HEAD)$(git diff --quiet || echo +)
clang++ -o bin/edk2_amd64/syz-executor executor/executor.cc \
    -m64 -O2 -pthread -Wall -Wno-array-bounds \
    -Wno-unused-but-set-variable -Wno-unused-command-line-argument \
    -std=c++17 -I. -Iexecutor/_include \
    -DGOOS_edk2=1 -DGOARCH_amd64=1 -DHOSTGOOS_linux=1 \
    -DGIT_REVISION=\"${GIT_REV}\"
```

**Important:** The executor must be built with the host's native toolchain.
Building it inside `syz-env` produces a binary linked against a newer glibc
that may not be available on the host.

**Re-running `make target` or `make manager` inside `syz-env` will
overwrite the executor** with the container's glibc-2.38-linked copy
and the manager will immediately error with `GLIBC_2.38 not found`.
If you hit that after any grammar or manager rebuild, re-run the
native `clang++` line above.

## Running with syz-manager

Create a config file (e.g. `edk2-manager.cfg`):

```json
{
    "name": "edk2-fuzz",
    "target": "edk2/amd64",
    "http": "localhost:56741",
    "workdir": "/path/to/workdir-edk2",
    "syzkaller": "/path/to/syzkaller",
    "image": "/path/to/edk2/Build/OvmfX64/NOOPT_GCC5/FV/OVMF_VARS.fd",
    "procs": 1,
    "sandbox": "none",
    "type": "qemu",
    "cover": true,
    "reproduce": false,
    "vm": {
        "count": 2,
        "cpu": 2,
        "mem": 1024,
        "qemu": "qemu-system-x86_64",
        "efi_code_device": "/path/to/edk2/Build/OvmfX64/NOOPT_GCC5/FV/OVMF_CODE.fd",
        "efi_vars_device": "/path/to/edk2/Build/OvmfX64/NOOPT_GCC5/FV/OVMF_VARS.fd"
    }
}
```

Run the manager:

```bash
bin/syz-manager -config edk2-manager.cfg
```

Open the web UI at `http://localhost:56741`. If running on a remote server,
tunnel the port: `ssh -L 56741:localhost:56741 your-server`.

## End-to-end example: full-sanitizer fwsnap campaign

Clone, build, and launch a TCG-snapshot fuzzing campaign with every
sanitizer active:

```bash
# 1. Check out the two repos side by side
git clone git@github.com:cglosner/edk2.git edk2-syzkaller
git -C edk2-syzkaller checkout syzkaller-edk2
git -C edk2-syzkaller submodule update --init --recursive
git clone git@github.com:cglosner/syzkaller.git syzkaller

# 2. Build OVMF with full sanitizer coverage
cd edk2-syzkaller
make -C BaseTools -j$(nproc)
export GCC5_BIN=$PWD/BaseTools/BinWrappers/PosixLike/gcc-wrap/
. ./edksetup.sh
build -p OvmfPkg/OvmfPkgX64.dsc -a X64 -t GCC5 -b NOOPT \
      -D SYZ_AGENT_ENABLE=TRUE -D ASAN_ENABLE=TRUE \
      -D ASAN_INSTRUMENT=TRUE -D UBSAN_INSTRUMENT=TRUE \
      -D FD_SIZE_IN_KB=8192 -n $(nproc)

# 3. Build syzkaller manager + target + host-native executor
cd ../syzkaller
CI=true ./tools/syz-env make manager
CI=true ./tools/syz-env make TARGETOS=edk2 TARGETARCH=amd64 TARGETVMARCH=amd64 target
GIT_REV=$(git rev-parse HEAD)$(git diff --quiet || echo +)
clang++ -o bin/edk2_amd64/syz-executor executor/executor.cc \
    -m64 -O2 -pthread -Wall -Wno-array-bounds \
    -Wno-unused-but-set-variable -Wno-unused-command-line-argument \
    -std=c++17 -I. -Iexecutor/_include \
    -DGOOS_edk2=1 -DGOARCH_amd64=1 -DHOSTGOOS_linux=1 \
    "-DGIT_REVISION=\"${GIT_REV}\""

# 4. Build qemu-fwfuzz (once) — plugins/libfwsnap.so is used by fwsnap mode
git clone -b dev/firmware-fuzz-coverage https://github.com/cglosner/qemu.git qemu-fwfuzz
cd qemu-fwfuzz
./configure --target-list=x86_64-softmmu --disable-werror --disable-docs \
            --disable-tools --disable-gtk --disable-vnc --enable-plugins
make -j$(nproc) qemu-system-x86_64 contrib/plugins/libfwsnap.so
mv build build-fwfuzz

# 5. Create a manager config (save as edk2-manager-fwsnap.cfg)
cd ../syzkaller
cat > tools/syz-edk2-fuzz/edk2-manager-fwsnap.cfg <<EOF
{
  "name": "edk2-fwsnap",
  "target": "edk2/amd64",
  "http": "localhost:56755",
  "workdir": "$(pwd)/workdir-edk2-fwsnap",
  "syzkaller": "$(pwd)",
  "kernel_obj": "$(pwd)/../edk2-syzkaller/Build/OvmfX64/NOOPT_GCC5/X64",
  "kernel_src": "$(pwd)/../edk2-syzkaller",
  "kernel_build_src": "$(pwd)/../edk2-syzkaller",
  "image": "/tmp/syz-edk2-ovmf-vars.fd",
  "procs": 1,
  "sandbox": "none",
  "type": "qemu",
  "cover": true,
  "reproduce": false,
  "enable_syscalls": ["syz_mmap", "syz_edk2_run_program"],
  "vm": {
    "count": 1,
    "cpu": 1,
    "mem": 1024,
    "qemu": "qemu-system-x86_64",
    "tcg_snapshot": true,
    "qemu_fwfuzz": "$(pwd)/../qemu-fwfuzz/build-fwfuzz/qemu-system-x86_64",
    "efi_code_device": "$(pwd)/../edk2-syzkaller/Build/OvmfX64/NOOPT_GCC5/FV/OVMF_CODE.fd",
    "efi_vars_device": "/tmp/syz-edk2-ovmf-vars.fd"
  }
}
EOF
cp ../edk2-syzkaller/Build/OvmfX64/NOOPT_GCC5/FV/OVMF_VARS.fd /tmp/syz-edk2-ovmf-vars.fd

# 6. Launch
./bin/syz-manager -config tools/syz-edk2-fuzz/edk2-manager-fwsnap.cfg
```

Watch the web UI at http://localhost:56755 for `corpus`, `coverage`,
and `crashes`. First boot takes 5-10 minutes (ASan-instrumented OVMF
under TCG) to reach the snapshot point; subsequent fuzz iterations
restore from the snapshot and execute at 100+/min.

## Running with syz-edk2-fuzz (standalone)

For quick testing without the full syz-manager pipeline, use the standalone
fuzzer:

```bash
# Build
CI=true ./tools/syz-env go build -o bin/syz-edk2-fuzz ./tools/syz-edk2-fuzz/

# Run a 5-minute campaign
bin/syz-edk2-fuzz \
    -ovmf-code /path/to/OVMF_CODE.fd \
    -ovmf-vars /path/to/OVMF_VARS.fd \
    -duration 5m \
    -use-grammar \
    -total-funcs 24248 \
    -syz-prog \
    -prog-log /tmp/programs.log
```

Or use the all-in-one script that builds everything and runs:

```bash
DURATION=5m bash tools/syz-edk2-fuzz/run-fuzz.sh
```

### Useful environment variables for run-fuzz.sh

| Variable | Default | Description |
|---|---|---|
| `DURATION` | `30s` | Fuzzing campaign length |
| `SKIP_BUILD` | `0` | Set to `1` to skip EDK2 + syzkaller rebuild |
| `ASAN_INSTRUMENT` | `FALSE` | Enable ASan instrumentation in DXE modules |
| `UBSAN_INSTRUMENT` | `FALSE` | Enable UBSan instrumentation |
| `TOTAL_FUNCS` | `31724` | Total functions for coverage % calculation |
| `USE_GRAMMAR` | `1` | Use syzlang grammar (vs hand-rolled random) |
| `GRAMMAR_SKIP` | `400,401` | Comma-separated API IDs to skip (HII by default) |

## What gets fuzzed

The fuzzer exercises the following UEFI surfaces through 90+ API call types:

### Boot / Runtime Services
- Variable Services: SetVariable, GetVariable, QueryVariableInfo, GetNextVariableName
- Memory Services: AllocatePool, FreePool, AllocatePages, FreePages, CopyMem, SetMem
- Time Services: GetTime, SetTime, Stall, SetWatchdogTimer
- Event Services: CreateEvent, CloseEvent, SignalEvent, SetTimer, WaitForEvent
- TPL Services: RaiseTPL

### Protocol method calls
- **Storage**: BlockIo Read/Write, DiskIo Read/Write
- **Network**: IP4 Configure/Transmit/GetModeData, UDP4 Configure/Transmit,
  TCP4 Configure/Connect/Transmit, DHCP4 Configure/Start, ARP Configure/Add/Request,
  MNP Configure/Transmit, SNP Transmit/Receive/GetStatus/Initialize
- **File System**: SimpleFs OpenVolume, File Open/Read/Write/GetInfo/SetInfo/Close/Delete
- **PCI**: PciIo Mem/IO/Pci Read/Write, PciRootBridgeIo Mem/Pci Read/Write
- **USB**: UsbIo ControlTransfer, BulkTransfer
- **Graphics**: GOP Blt/SetMode/QueryMode
- **Console**: SimpleTextOut OutputString/SetMode/SetAttribute/ClearScreen,
  SimpleTextIn Reset/ReadKeyStroke
- **HII**: Database NewPackageList/RemovePackageList/UpdatePackageList/ExportPackageLists,
  String NewString/GetString/SetString/GetLanguages
- **Device Path**: DevicePathFromText, DevicePathToText
- **ACPI**: GetAcpiTable, InstallAcpiTable
- **ASan**: Poison/Unpoison/Report (for ASan-instrumented builds)

### QEMU devices attached

The VM configuration includes devices that cause the corresponding firmware
drivers to load:

| Device | QEMU flag | Firmware drivers loaded |
|---|---|---|
| VGA | `-device VGA` | QemuVideoDxe, GraphicsConsoleDxe |
| virtio-net | `-device virtio-net-pci` | VirtioNetDxe, SnpDxe, MnpDxe, ArpDxe, Ip4Dxe, Udp4Dxe, Tcp4Dxe, Dhcp4Dxe |
| virtio-blk | `-device virtio-blk-pci` | VirtioBlkDxe, PartitionDxe, DiskIoDxe |
| AHCI/SATA | `-device ich9-ahci` | SataController, AtaAtapiPassThru, AtaBusDxe |
| NVMe | `-device nvme` | NvmExpressDxe |
| FAT disk | `-drive file=fat:rw:dir` | FatDxe, PartitionDxe |
| xHCI USB | `-device qemu-xhci` | XhciDxe, UsbBusDxe, UsbMassStorageDxe |
| Serial | `-device isa-serial` | SerialDxe |

## Coverage

The standalone `syz-edk2-fuzz` tool reports coverage as a percentage of total
DXE functions. Recount after a build with:

```bash
find /path/to/edk2/Build/OvmfX64/NOOPT_GCC5/X64/ -name '*.dll' \
    -exec nm --defined-only {} + 2>/dev/null | grep -c ' [tT] '
```

Pass the result as `-total-funcs` or `TOTAL_FUNCS=`.

Typical results with a 1-hour campaign: **~46% of DXE functions** covered.

## Crash reporting

Crashes are detected from the OVMF debug log (`-debugcon` output) by matching:
- `!!!! X64 Exception Type` — CPU exceptions (null deref, page fault, etc.)
- `ASSERT [` — EDK2 ASSERT failures
- `==ERROR: AddressSanitizer:` — ASan violations (with `ASAN_INSTRUMENT=TRUE`)

The standalone fuzzer writes each program's call IDs to `-prog-log`, so
crash-triggering programs can be identified and replayed.

## Symbolization

To symbolize crash PCs back to source lines, use the helper script:

```bash
python3 tools/syz-edk2-fuzz/symbolize.py \
    --debug-log /path/to/edk2-debug.log \
    --build-dir /path/to/edk2/Build/OvmfX64/NOOPT_GCC5/X64/
```

This parses `Loading driver at` lines from the debug log to build a module
load map, then uses `addr2line` on the per-module `.dll` files.

## Known limitations

- **Coverage-guided mutation in syz-manager** works. The firmware-side
  coverage gate (SyzCoverReset/SyzCoverStop) scopes PC recording to
  program dispatch windows, and the executor feeds signal to the manager's
  corpus. Programs that discover new firmware code paths are kept and
  mutated. Set `"cover": true` in the syz-manager config.
- **Coverage symbolization in syz-manager web UI** is not yet implemented.
  The `/cover` page won't show source-line coverage until the per-module
  ELF backend is added to map DXE `.dll` DWARF symbols to PCs.
- **No KVM snapshot fuzzing** yet. Each auto-restart reboots OVMF from
  scratch (~6s). Snapshot-restore would eliminate this overhead.
- **Single-call programs only.** Resource chaining across calls (e.g.
  alloc -> use -> free -> use-after-free) requires adding `resource` types
  to the syzlang grammar.
- **SMM fuzzing** is not integrated. SMI handler fuzzing requires a separate
  harness (see `tools/syz-edk2-smi-fuzz/`).

## NVRAM persistence across fwsnap iterations

OVMF_VARS pflash is mapped above 0xFF000000 — well outside the fwsnap
snapshot region (`0x3C000000:0x04000000` by default, see
`vm/qemu/fwsnap_edk2.go:buildFwsnapPluginArg`). As a result,
`SetVariable` writes survive ACROSS iterations within the same VM:
iteration N writes a variable, iteration N+1 can read it. This is
"stateful fuzzing" for the variable store.

Persistence across VM restarts (after a crash) is NOT preserved —
each new VM gets a fresh copy of `OVMF_VARS.fd` from
`EfiVarsDevice`. That's deliberate (a crashed VM could have left the
varstore corrupted). To experiment with cross-restart persistence,
point `EfiVarsDevice` at a long-lived copy and remove the per-VM
duplicate in `vm/qemu/qemu.go` (search `copyFile(inst.cfg.EfiVarsDevice`).

## Planted-bug validation mode

Build with `-D SYZ_BUGS_DISPATCH_INJECT=TRUE` to enable the 15
handler tripwires (see `docs/edk2/bug-injection-catalog.md`). Each
tripwire triggers a deterministic ASan/UBSan primitive in
`MdeModulePkg/Library/SyzBugsLib/SyzBugsLib.c` when the fuzzer
reaches the dispatch handler with a specific magic value. Use the
`tools/syz-edk2-fuzz/plant-seeds/` corpus for deterministic
validation. Leave `INJECT=FALSE` for production runs.

## Fault trampoline + MMIOCS enforcement

Phase 2 adds two mutes for fuzzer-induced noise:
- `SyzFaultGuard` (`OvmfPkg/SyzAgentDxe/SyzFaultGuard.c`) installs
  custom `#DE/#UD/#GP/#PF` handlers + a `SetJump` trampoline.
  Hardware faults from fuzzer-chosen CpuIo/MSR addresses are trapped
  and returned as error instead of crashing the firmware.
- `-D MMIOCS_ENFORCE=TRUE` turns MMIOCS from log-only into
  enforcing: unresolved MMIO addresses are rejected at the
  dispatcher before the CPU fires the fault.

Both are on by default in the production build config; disable only
for debugging noise you're actually chasing.

## Further reading

- [docs/edk2_design.md](../edk2_design.md) - Detailed design document
- [docs/edk2_grammar_walkthrough.md](../edk2_grammar_walkthrough.md) - Grammar walkthrough
- [docs/edk2_asan_handoff.md](../edk2_asan_handoff.md) - ASan Linux kernel handoff plan
- [docs/edk2/bug-injection-catalog.md](bug-injection-catalog.md) - 15 planted-bug tripwire catalog
- [docs/edk2/crash-triage.md](crash-triage.md) - Crash triage rounds 1 + 2
