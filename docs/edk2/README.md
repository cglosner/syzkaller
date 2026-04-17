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

### Optional: ASan/UBSan instrumentation

To enable AddressSanitizer for DXE modules (heap, stack, globals):

```bash
build -p OvmfPkg/OvmfPkgX64.dsc -a X64 -t GCC5 -b NOOPT \
    -D SYZ_AGENT_ENABLE=TRUE \
    -D ASAN_ENABLE=TRUE \
    -D ASAN_INSTRUMENT=TRUE \
    -D UBSAN_INSTRUMENT=TRUE \
    -D FD_SIZE_IN_KB=8192 \
    -n $(nproc)
```

ASan shadow memory is backed by the ivshmem region (offset `0x200000`),
so it doesn't consume firmware RAM.

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

## Further reading

- [docs/edk2_design.md](../edk2_design.md) - Detailed design document
- [docs/edk2_grammar_walkthrough.md](../edk2_grammar_walkthrough.md) - Grammar walkthrough
- [docs/edk2_asan_handoff.md](../edk2_asan_handoff.md) - ASan Linux kernel handoff plan
