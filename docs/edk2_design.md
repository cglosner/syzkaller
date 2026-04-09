# Design: Adding EDK2 (UEFI/OVMF) fuzzing support to syzkaller

Status: design proposal — no code yet.
Audience: contributors familiar with the syzkaller codebase who want to add a
new fuzz target for the EDK2 UEFI reference implementation (specifically OVMF,
the QEMU/KVM build of EDK2). This document is intended to be detailed enough
that the implementation can proceed without having to re-derive the design.

This document is patterned on [docs/syzos.md](syzos.md) and
[docs/adding_new_os_support.md](adding_new_os_support.md). Read those first.

---

## 1. Background

### 1.1 What syzkaller fuzzes today

`syzkaller` is a coverage-guided fuzzer that drives an OS kernel by issuing
sequences of declaratively-described entry points (syscalls or pseudo-syscalls).
The pieces relevant to a new target are:

- **`syzlang` descriptions** — DSL files in [sys/$OS/](../sys) describing the
  entry points, types, resources, and pseudo-syscalls. Compiled into Go data
  by [pkg/compiler](../pkg/compiler) via [sys/syz-sysgen](../sys/syz-sysgen).
- **`prog` package** — in-memory AST of generated programs, mutation,
  minimization, encoding/decoding. See [prog/target.go](../prog/target.go) and
  [prog/prog.go](../prog/prog.go).
- **`syz-executor`** — C++ runtime ([executor/executor.cc](../executor/executor.cc))
  that interprets the binary `exec` form of programs and calls into the target.
  Per-OS specifics live in `executor/executor_$OS.h` and `executor/common_$OS.h`.
- **`syz-manager`** — Go orchestrator that runs VMs, distributes inputs, and
  collects coverage/crashes. VM backends live in [vm/](../vm), build helpers in
  [pkg/build/](../pkg/build), and crash parsers in [pkg/report/](../pkg/report).
- **Target descriptors** — [sys/targets/targets.go](../sys/targets/targets.go)
  registers OS/arch tuples and their flags (`SyscallNumbers`, `HostFuzzer`,
  `ExecutorUsesForkServer`, …).
- **Per-OS init** — `sys/$OS/init.go` registers `MakeDataMmap`, `Neutralize`,
  `SpecialTypes`, and friends.

There are two architectural patterns precedent already exists for that are
directly relevant to EDK2:

1. **`HostFuzzer` mode** (Fuchsia, Starnix). The Go side runs on the host, only
   `syz-executor` runs on the target, and the target may not have classic
   syscall numbers (`SyscallNumbers: false`). See the `Fuchsia` and `Trusty`
   blocks in [sys/targets/targets.go](../sys/targets/targets.go) and the
   [HostFuzzer flag](../sys/targets/targets.go#L83).
2. **SYZOS** (`sys/linux/dev_kvm_amd64.txt`,
   `executor/common_kvm_amd64_syzos.h`, [docs/syzos.md](syzos.md)). syzkaller
   doesn't try to fuzz a real OS by emitting raw guest instructions —
   instead it runs a tiny C "guest agent" inside KVM and the fuzzer emits a
   sequence of high-level commands that the guest interprets. The fuzzer
   mutates the *commands*, not raw assembly. This pattern is the closest fit
   for fuzzing UEFI.

### 1.2 What EDK2 / OVMF is

EDK2 is the open-source UEFI reference implementation maintained by TianoCore.
The relevant pieces of the upstream tree (now in `/home/gl055/research/projects/edk2`):

- **`MdePkg/`** — UEFI/PI specification headers. Defines `EFI_BOOT_SERVICES`,
  `EFI_RUNTIME_SERVICES`, `EFI_SYSTEM_TABLE`, and the protocol headers in
  `MdePkg/Include/Protocol/`. These are the "syscalls" of UEFI.
- **`MdeModulePkg/`** — Core DXE/PEI drivers, including the variable store
  ([MdeModulePkg/Universal/Variable/RuntimeDxe](../../edk2/MdeModulePkg/Universal/Variable/RuntimeDxe)),
  HII database, network stack, file system, etc.
- **`OvmfPkg/`** — The QEMU/KVM-targeted EDK2 build. Produces an `OVMF.fd`
  flash image (or split `OVMF_CODE.fd` + `OVMF_VARS.fd`) loaded by QEMU as
  pflash. Also contains
  [OvmfPkg/QemuFlashFvbServicesRuntimeDxe](../../edk2/OvmfPkg/QemuFlashFvbServicesRuntimeDxe)
  (variable backing store), the SEC entry point, and PlatformPei.
- **`SecurityPkg/`** — Authenticated variables, secure boot, TCG/TPM stack.
- **`NetworkPkg/`** — UEFI network stack (DHCP, TCP, HTTP, iSCSI, TLS).
- **`EmulatorPkg/`** — Builds DXE/PEI as a *host* process for development.
  Produces `Build/EmulatorX64/DEBUG_GCC/X64/Host`. See
  [EmulatorPkg/Readme.md](../../edk2/EmulatorPkg/Readme.md). This is the
  closest analogue to Fuchsia/Starnix host fuzzing.
- **`UnitTestFrameworkPkg/`** — Existing host-test infrastructure
  (`<Pkg>/Test/<Pkg>HostTest.dsc`). EDK2 already has the toolchain plumbing
  to build a UEFI module as a host ELF/PE binary.
- **`BaseTools/Conf/tools_def.template`** — Toolchain definitions
  (`GCC_X64_CC_FLAGS`, `NOOPT_GCC_X64_CC_FLAGS`, …). Important: EDK2 code is
  compiled with `EFIAPI` calling convention (`__attribute__((ms_abi))` on
  GCC X64), `-mno-red-zone`, `-fpie`, `-mcmodel=small`, no standard libc.

There is **no system call interface**. UEFI exposes function pointer tables
hanging off the EFI System Table. There is **no userspace/kernelspace split**
during boot — all DXE/PEI/SMM code runs at CPL0 in identity-mapped long mode
(or 32-bit mode pre-handoff). After `ExitBootServices()` only the runtime
services remain, in the runtime memory map.

EDK2 firmware is therefore neither a "syscall API" nor a regular ELF binary;
it is closer in spirit to SYZOS than to Linux.

---

## 2. What "fuzzing EDK2" actually means

UEFI is a large surface. Before settling on a design we need to scope which
attack surfaces we want to reach, because each one constrains the build mode,
the way inputs are delivered, and the way coverage is collected.

Categories of bugs that have been found in EDK2 historically:

| Category | Example surfaces | Reachable from |
| --- | --- | --- |
| Variable services | `SetVariable`, authenticated variables, variable policy | DXE/Runtime |
| Image loading | PE/COFF parser, FV/FFS parser, capsule update | DXE |
| Network stack | iPXE, HTTPBoot, DHCPv4/v6, TCP, TLS | DXE (BDS phase) |
| File systems | FAT, ext, NTFS in FatPkg/third party | DXE |
| HII / forms | IFR/UEFI HII opcode parser, font, string packs | DXE |
| SMI handlers | OvmfPkg/CpuHotplugSmm, variable SMM, dispatcher | SMM |
| Boot services / protocols | `LocateProtocol`, `OpenProtocol` ordering, device path parsing | DXE |
| ACPI / SMBIOS / DT consumers | ACPI parsers, SMBIOS 3.x | DXE |
| TCG2 / TPM | TPM2 command marshalling, event log | DXE |

A useful split:

- **Stateful protocol/runtime fuzzing** — needs a (mostly) booted firmware
  with the system table and protocol database populated. SetVariable, HII,
  network stack, device path, capsule.
- **Pure parser fuzzing** — single-shot, no state, e.g. PE/COFF parser, IFR
  parser, FAT parser. Fits a libFuzzer-like model better than syzkaller.

This proposal focuses on the **stateful** category, which is exactly what
syzkaller is good at and what tools like libFuzzer/AFL handle poorly. Pure
parser fuzzing already has a home in
[UnitTestFrameworkPkg](../../edk2/UnitTestFrameworkPkg) host-tests with
libFuzzer; we should not duplicate that.

---

## 3. Design choices

### 3.1 Where the firmware runs

Three options were considered:

| # | Option | Pros | Cons |
| --- | --- | --- | --- |
| A | **OVMF inside QEMU/KVM**, instrument the firmware, talk to it via QEMU device (fw_cfg, ivshmem, debug port) | Real firmware code, KVM acceleration, identical to production binaries, snapshot fuzzing possible via KVM dirty rings | Complex coverage path, no syscalls — must build a shim "agent" image, slow VM boot, fragile crash detection |
| B | **EmulatorPkg** built as a Linux/macOS host process | Easy to instrument with `-fsanitize-coverage=trace-pc-guard`, no VM, can use ASAN/UBSAN, fits `HostFuzzer` mode like Fuchsia | Only covers DXE drivers compiled into the emulator; SEC/PEI/SMM and arch-specific code paths are stubbed; firmware diverges from production OVMF |
| C | **Custom syzkaller "EDK2 host" binary** that links MdePkg/MdeModulePkg as a library and calls protocol entry points directly from C++ | Maximum control, fast | Re-implementing what EmulatorPkg already does, huge engineering cost, code drift, unrealistic environment |

**Recommendation: do A as the primary target, treat B as an optional secondary
target.** A is the only path that exercises the real OvmfPkg code paths
(QemuFlashFvbServicesRuntimeDxe, PlatformPei, the real CPU exception handler,
etc.) and matches the existing SYZOS pattern. B is useful as a fast smoke-test
loop and for catching DXE bugs before paying QEMU's boot cost, but it should
not be the only mode.

The rest of this document assumes design A unless explicitly noted.

### 3.2 How the fuzzer talks to the firmware

This is the central design question. We need a bidirectional channel that:

1. The host (`syz-executor` running on Linux next to `qemu-system-x86_64`) can
   write a sequence of commands into.
2. A driver inside the firmware can read commands from, dispatch them, and
   write results back.
3. Survives the firmware boot transitions (PEI → DXE → BDS).
4. Does not require a UEFI shell, OS loader, or network stack — those are the
   things we want to fuzz, not depend on.

Option chosen: **QEMU `fw_cfg` for command transport + a custom DXE driver
("`SyzAgentDxe`") that owns the dispatch loop**, plus an MMIO/`ivshmem` region
for high-bandwidth data and coverage.

Why fw_cfg:

- It is already supported by OvmfPkg (see
  [OvmfPkg/Library/QemuFwCfgLib](../../edk2/OvmfPkg/Library/QemuFwCfgLib) and
  [OvmfPkg/Include/IndustryStandard/QemuFwCfg.h](../../edk2/OvmfPkg/Include/IndustryStandard/QemuFwCfg.h)).
- It is host-controllable from outside the guest via `-fw_cfg
  name=opt/syz/program,file=...` (read-only at boot) or, more importantly,
  via the QEMU monitor / QMP, which `syz-executor` can drive over a Unix
  socket the same way `vm/qemu` already manages QEMU.
- It does not require a network device, disk, or shell.

The "execute a program" step then looks like:

```
host (syz-executor)                      guest (SyzAgentDxe)
-------------------                      --------------------
write program bytes into ivshmem
write fw_cfg key opt/syz/program_size
qmp: cont                          ───►  on entry, locate fw_cfg
                                         read program_size, mmio-copy
                                         dispatch loop:
                                           parse next syz_edk2_call
                                           call corresponding handler
                                           append result to results page
                                         write SYZ_EDK2_DONE marker
                                  ◄───   doorbell via debug exit / ivshmem
read results page from ivshmem
```

`SyzAgentDxe` lives inside OVMF and is loaded as one of the last DXE drivers
(`DEPEX TRUE`, run after the variable services and the network stack are up).
It sits in a loop waiting for the next program. After each program it
optionally resets some VM state (see §3.5) and waits again.

### 3.3 Coverage collection

Two complementary mechanisms:

1. **Compile-time instrumentation of EDK2** with
   `-fsanitize-coverage=trace-pc-guard`. Provide a single C file
   (`SyzCoverDxe/SanitizerCovTracePc.c`) implementing
   `__sanitizer_cov_trace_pc_guard_init` and
   `__sanitizer_cov_trace_pc_guard`. Each guard slot writes the PC into a
   ring buffer in a fixed physical page that the host has mmaped via
   `ivshmem`. This mirrors what
   [executor/executor_test.h](../executor/executor_test.h) does for the
   fallback test target — see the `__sanitizer_cov_trace_pc` shim there.

   The instrumentation must be applied selectively. EDK2's build system reads
   `*_*_*_CC_FLAGS` per-toolchain in
   [BaseTools/Conf/tools_def.template](../../edk2/BaseTools/Conf/tools_def.template).
   We add a new toolchain tag (e.g. `GCC5SYZ`) that reuses `GCC_X64_CC_FLAGS`
   and appends:
   ```
   -fsanitize-coverage=trace-pc-guard
   -fno-discard-value-names
   ```
   *Critical:* coverage instrumentation must NOT be applied to:
   - The reset vector and SEC (`OvmfPkg/ResetVector`, `OvmfPkg/Sec`) —
     they run before any heap/stack we control exists.
   - `MdePkg/Library/BaseLib` low-level helpers used by the trace functions
     themselves (otherwise infinite recursion).
   - `SyzCoverDxe` itself.
   This is done by adding `MODULE_TYPE` overrides in the OVMF DSC like the
   `[BuildOptions]` blocks already used for ASAN/UBSAN selectively.

2. **KVM PT / Intel PT (optional, future)** — for the parts we cannot
   instrument (SEC, very early PEI). Same model as `pkg/cover` already
   handles for kcov-on-Linux: data is decoded host-side. Out of scope for
   the first cut, but the design must not preclude it.

The host side already has the abstractions needed. `pkg/cover/report.go`,
`pkg/symbolizer`, and `pkg/cover/backend` all assume PCs come back as
`uint64`. They're agnostic to which KASLR-style remapping we apply, as long
as we hand them a consistent text range. We will configure
`KernelAddresses.TextStart`/`TextEnd` in `sys/targets/targets.go` to the
fixed OVMF code range (typically `0x0000_0000_FFE0_0000` upward for the
4 MiB pflash).

### 3.4 Crash detection

Three failure modes need to map to `report.Report`:

| Symptom | Detection path | Maps to |
| --- | --- | --- |
| Guest CPU exception (page fault, #UD, #GP) | OVMF's existing `CpuExceptionHandlerLib` writes a register dump to the QEMU debug-con port (port `0x402` / `0x3F8`), then the SyzAgent handler intercepts via an EXCEPTION_HANDLER and calls `gBS->Exit` | "kernel panic" style report; serial log captured by `vm/qemu` via `-serial` |
| ASSERT() / DEBUG ((EFI_D_ERROR …)) loop | DEBUG output already goes through `DebugLib` to QEMU debug-con | parsed by a new `pkg/report/edk2.go` |
| `SyzAgentDxe` watchdog: program ran > N ms with no progress | Host-side timeout in QEMU monitor + `kill -KILL` of qemu | "no output from test machine" |
| Sanitizer report (if we add an EDK2 ASAN port) | DEBUG print of UBSAN/ASAN style message | parsed by `pkg/report/edk2.go` |

The serial-port → host path is identical to how every other VM target works
in syzkaller; nothing special is needed in `vm/qemu` beyond making sure the
char-dev is wired up.

### 3.5 Per-program state isolation

This is where EDK2 fuzzing is genuinely harder than Linux fuzzing. UEFI has
no `fork()`. Three options:

1. **Boot-fresh per program** — restart QEMU for every program. Works,
   correct, **catastrophically slow** (OVMF cold-boot is ~1–2s). Not viable
   for the main loop, useful for repro/minimization.
2. **KVM snapshot fuzzing** — boot OVMF once, snapshot at the entry of
   `SyzAgentDxe`'s dispatch loop, restore snapshot per program. syzkaller
   already has snapshot infrastructure (see the `snapshot` syscall attribute
   and the `*snapshot` field on `instance` in
   [vm/qemu/qemu.go](../vm/qemu/qemu.go)). This is the recommended mode.
3. **Logical reset inside the agent** — `SyzAgentDxe` records "interesting"
   mutated state (variables created, protocols installed, events open) and
   tears them down between programs. Cheap but incomplete; misses kernel
   pool corruption.

Plan: implement option 3 first as a baseline and option 2 as the production
mode. Option 1 is the fallback that pkg/repro will use for minimization
(set with the `no_minimize` attribute on calls that mutate persistent state,
following the existing `compressed_image` precedent in
[docs/syscall_descriptions_syntax.md](syscall_descriptions_syntax.md)).

### 3.6 Why not "just reuse SYZOS"

SYZOS runs as an L2 guest *under* a Linux L1 — its purpose is to fuzz the
KVM host's hypervisor logic. EDK2 needs to be the L1 itself: the firmware is
the SUT, and Linux is not in the picture. The mechanical pieces are similar
(command page, dispatch loop in `if/else if` chain so the compiler doesn't
emit a `.rodata` jump table) but the lifecycle, the entry point, the memory
layout, and the coverage path are all different. We **borrow the dispatch
pattern and the syzlang command-array idiom from SYZOS, but do not extend
SYZOS itself.**

---

## 4. Concrete file-by-file changes

What follows is the punch-list to land "edk2/amd64" as a first-class syzkaller
target. Filenames marked **NEW** do not exist yet.

### 4.1 syzkaller side (Go / C++)

#### 4.1.1 Target registration

- [sys/targets/targets.go](../sys/targets/targets.go) — add an `EDK2` constant
  next to `Linux`/`Fuchsia` and a new entry in the `List` map:

  ```go
  const EDK2 = "edk2"

  // ... in List:
  EDK2: {
      AMD64: {
          PtrSize:          8,
          PageSize:         4 << 10,
          CCompiler:        "clang",
          CFlags:           []string{"-m64"},
          // OVMF flash (CODE) is mapped at the top of the 4 GiB window.
          KernelAddresses: KernelAddresses{
              TextStart: 0x00000000FFE00000,
              TextEnd:   0x0000000100000000,
          },
      },
  },
  ```

  And in `var oses`:

  ```go
  EDK2: {
      // syz-executor runs on the Linux host next to qemu, the firmware
      // does not have syscall numbers.
      BuildOS:                Linux,
      SyscallNumbers:         false,
      ExecutorUsesForkServer: false,
      HostFuzzer:             true,
      KernelObject:           "OVMF.fd",
  },
  ```

  The `HostFuzzer: true` flag is the same one Fuchsia uses, and is what tells
  the rest of syzkaller "the executor process lives on the host".

#### 4.1.2 sys/edk2/ — descriptions **NEW**

- `sys/edk2/init.go` **NEW** — minimal target init, follows
  [sys/trusty/init.go](../sys/trusty/init.go) almost verbatim:

  ```go
  // Copyright 2026 syzkaller project authors. All rights reserved.
  // Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

  package edk2

  import (
      "github.com/google/syzkaller/prog"
      "github.com/google/syzkaller/sys/targets"
  )

  func InitTarget(target *prog.Target) {
      target.MakeDataMmap = targets.MakeSyzMmap(target)
  }
  ```

- `sys/edk2/edk2.txt` **NEW** — top-level description. Follows the
  syzlang style of [sys/linux/dev_kvm_amd64.txt](../sys/linux/dev_kvm_amd64.txt):
  one pseudo-syscall, `syz_edk2_run_program`, that takes a fixed-size array
  of `syz_edk2_call` union variants. For example:

  ```
  # Copyright 2026 syzkaller project authors. All rights reserved.
  # Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

  meta arches["amd64"]

  resource edk2_handle[int64]
  resource edk2_event[int64]
  resource edk2_variable_name[ptr64[in, string]]

  syz_edk2_run_program(prog ptr[in, edk2_program])

  edk2_program {
      ncalls  len[calls, int32]
      calls   array[syz_edk2_call, 1:32]
  }

  type edk2_api[NUM, PAYLOAD] {
      call    const[NUM, int32]
      size    bytesize[parent, int32]
      payload PAYLOAD
  }

  syz_edk2_call [
      set_variable        edk2_api[100, edk2_set_variable]
      get_variable        edk2_api[101, edk2_get_variable]
      query_variable_info edk2_api[102, edk2_query_variable_info]
      allocate_pool       edk2_api[200, edk2_allocate_pool]
      free_pool           edk2_api[201, edk2_free_pool]
      allocate_pages      edk2_api[202, edk2_allocate_pages]
      install_protocol    edk2_api[300, edk2_install_protocol]
      locate_protocol     edk2_api[301, edk2_locate_protocol]
      hii_new_package     edk2_api[400, edk2_hii_new_package]
      ...
  ] [varlen]
  ```

  Note the IDs (100, 101, …) **must match** the `SYZ_EDK2_API_*` enum in
  the agent's C source — exactly the same convention SYZOS uses (see
  [docs/syzos.md §6](syzos.md#6-developer-guide-how-to-add-a-new-command)).

  Subsequent files split by subsystem, mirroring `sys/linux/`:
  - `sys/edk2/variable.txt` — Runtime Services variable APIs.
  - `sys/edk2/protocol.txt` — Boot Services protocol DB.
  - `sys/edk2/memory.txt` — `AllocatePool`, `AllocatePages`, `FreePool`.
  - `sys/edk2/hii.txt` — HII database calls (often a bug source).
  - `sys/edk2/network.txt` — `EFI_TCP4_PROTOCOL`, `EFI_HTTP_PROTOCOL`, etc.
  - `sys/edk2/devicepath.txt` — device path parsing/composition.
  - `sys/edk2/capsule.txt` — capsule update.

  Constants (e.g. `EFI_VARIABLE_NON_VOLATILE = 0x1`) are extracted by
  `syz-extract` from the EDK2 headers (see §4.1.5). The `*.const` files are
  checked in alongside the `*.txt` files in the same commit, per
  [docs/contributing.md](contributing.md).

#### 4.1.3 syz-executor

- [executor/executor.cc](../executor/executor.cc) — Add a `#elif GOOS_edk2`
  branch where the other GOOS branches are. The branch is trivial because
  `HostFuzzer: true` means the executor runs on Linux: include
  `executor/executor_edk2.h` to provide `os_init` and `execute_syscall`.

- `executor/executor_edk2.h` **NEW** — analogous to
  [executor/executor_linux.h](../executor/executor_linux.h) but very small.
  It opens a Unix socket / shared-memory region exposed by the QEMU process,
  implements:
  - `os_init` — mmap data segment (just `mmap(... MAP_ANON|MAP_PRIVATE)` —
    same boilerplate as `executor_test.h`), connect to QEMU's QMP socket
    given by env var `SYZ_EDK2_QMP`.
  - `execute_syscall` — for the single pseudo-syscall
    `syz_edk2_run_program`, copies the program into shared memory, kicks the
    guest via fw_cfg/ivshmem doorbell, waits for the done flag (with
    timeout), and returns.

  No coverage code lives here — coverage flows directly from the guest agent
  into a host-mapped page (see §4.1.7).

- `executor/common_edk2.h` **NEW** — pseudo-syscall implementations. The
  only pseudo-syscall for the first cut is `syz_edk2_run_program`. Code style
  must follow the existing `common_kvm_amd64.h` exactly: each function
  guarded by `#if SYZ_EXECUTOR || __NR_syz_edk2_run_program`.

#### 4.1.4 pkg/build, pkg/report, vm/qemu

- `pkg/build/edk2.go` **NEW** — implements the
  [Builder interface](../pkg/build/build.go) for OVMF. Pattern follows
  `pkg/build/freebsd.go`. Minimum responsibilities:
  - Run EDK2's `BaseTools` setup (`make -C BaseTools`) once.
  - Run `build -p OvmfPkg/OvmfPkgX64.dsc -a X64 -t GCC5SYZ -b NOOPT
    -D SYZ_AGENT=TRUE`.
  - Copy the resulting `Build/OvmfX64/NOOPT_GCC5SYZ/FV/OVMF.fd` (and the
    split `OVMF_CODE.fd` / `OVMF_VARS.fd`) into the workdir.
  - Return the absolute path of `OVMF.fd` as the `KernelObject`.
  - SSH key generation is **not** needed — there is no OS, no SSH. Return
    a stub.

- [pkg/build/build.go](../pkg/build/build.go) — register the new builder
  next to the existing OS entries.

- `pkg/report/edk2.go` **NEW** — pattern follows
  [pkg/report/freebsd.go](../pkg/report/freebsd.go) (which itself derives
  from `pkg/report/bsd.go`). Recognises:
  - `ASSERT [<file>:<line>]` from `DEBUG_LIB`.
  - `!!!! X64 Exception Type - %02x` from `CpuExceptionHandlerLib`.
  - `Stack dump:` / `RIP - <addr>` lines.
  - `[SYZ-AGENT] panic:` lines emitted by `SyzAgentDxe` itself.

  Title-extraction regexes go in the same file. Tests under
  `pkg/report/testdata/edk2/`.

- [pkg/report/report.go](../pkg/report/report.go) — register `edk2` in the
  `ctors` map next to the others.

- [vm/qemu/qemu.go](../vm/qemu/qemu.go) — add an `archConfig` entry for
  `"edk2/amd64"`:

  ```go
  "edk2/amd64": {
      Qemu:     "qemu-system-x86_64",
      QemuArgs: strings.Join([]string{
          "-machine q35,accel=kvm",
          "-cpu host,migratable=off",
          "-nodefaults",
          "-nographic",
          "-no-reboot",
          "-serial", "stdio",
          "-device", "ivshmem-plain,memdev=syzcov",
          "-object", "memory-backend-file,id=syzcov,share=on,mem-path={{COVPATH}},size=2M",
      }, " "),
      // OVMF is loaded as pflash, NOT as -kernel.
      UseNewQemuImageOptions: true,
      CmdLine:                nil,
  },
  ```

  We also need to special-case the pflash arguments. The existing `Config`
  already has `EfiCodeDevice`/`EfiVarsDevice` fields (see lines 67–69 of
  [vm/qemu/qemu.go](../vm/qemu/qemu.go)) — those were added precisely for
  EFI booting and we reuse them: the manager config will set
  `efi_code_device` to `OVMF_CODE.fd` and `efi_vars_device` to a per-VM
  copy of `OVMF_VARS.fd`. The construction of the `-drive
  if=pflash,...` arguments already lives in `qemu.go`; we just need to
  make sure it is exercised when `target.OS == "edk2"` and not gated on a
  Linux-specific code path.

#### 4.1.5 sys/syz-extract

- [sys/syz-extract/extract.go](../sys/syz-extract/extract.go) — register an
  `edk2` extractor. EDK2 headers can be extracted with the existing
  generic extractor used by Fuchsia/NetBSD by feeding it a synthetic compile
  command:

  ```
  clang -E -nostdinc \
        -I $EDK2/MdePkg/Include \
        -I $EDK2/MdePkg/Include/X64 \
        -I $EDK2/MdeModulePkg/Include \
        -include Uefi.h \
        ...
  ```

  Constants we need on day one:
  - `EFI_VARIABLE_*` attributes (`UefiMultiPhase.h`).
  - `EfiBootServicesCode/Data`, `EfiRuntimeServicesCode/Data`, etc.
    (`UefiSpec.h`).
  - `TPL_APPLICATION/CALLBACK/NOTIFY/HIGH_LEVEL`.
  - `EFI_OPEN_PROTOCOL_*` attributes.
  - Selected protocol GUIDs (each becomes a 16-byte struct constant).

  GUIDs are awkward — they're not integer constants, they're 16-byte struct
  literals. Recommend handling them as `string` constants in syzlang for the
  first version (the agent looks them up by name) and revisiting later. See
  §6.5.

#### 4.1.6 Makefile, generated files

- [Makefile](../Makefile) — add `edk2/amd64` to the supported target tuples
  in the `extract` and `generate` rules. The pattern is identical to the
  existing entries.

- [sys/generated/](../sys/generated) — gets a new
  `edk2_amd64.gob.flate` after running `make generate`. Committed as part of
  the same commit as the descriptions.

#### 4.1.7 Coverage transport — host side

The agent's coverage page is exposed via `ivshmem-plain`. The host process
opens the same backing file, mmaps it shared, and treats the first page as
a `(uint32 nr_pcs, uint64 pcs[])` ring buffer.

This wires into the existing coverage path through `pkg/cover` by having
`executor_edk2.h::execute_syscall` drain the ring buffer into the per-call
cover slot in shared memory between the executor and `syz-manager`. From
that point on it is identical to every other target — `pkg/cover/report.go`
already understands "list of PCs in `[TextStart, TextEnd)`".

The PC values written by the guest are *guest physical / virtual addresses*,
which match the addresses in the OVMF `.debug` symbol file. We add a
helper in `pkg/build/edk2.go` to walk
`Build/OvmfX64/NOOPT_GCC5SYZ/X64/*/DEBUG/*.debug` and produce the
`vmlinux`-equivalent symbol-info file that `syz-symbolize` consumes.

### 4.2 EDK2 side (C)

These changes go into the EDK2 tree (which is *not* part of the syzkaller
repo) and live in a new `OvmfPkg/SyzAgentDxe` and `OvmfPkg/Library/SyzCoverLib`
subtree. They are tracked separately (recommended: a `syzkaller-edk2` branch
of EDK2 that we maintain alongside upstream, or a fork of OvmfPkg) but the
syzkaller-side build documentation must reference them and pull/build them
deterministically. Treat the EDK2 patch series as a build-time dependency the
same way we treat external kernel patches today.

#### 4.2.1 SyzAgentDxe — the in-firmware agent

`OvmfPkg/SyzAgentDxe/SyzAgentDxe.inf`, `.c`, `.h`. Skeleton:

- Module type `DXE_DRIVER`, `[Depex] gEfiVariableArchProtocolGuid AND
  gEfiHiiDatabaseProtocolGuid AND ...` so we run only after the subsystems
  we want to fuzz are up.
- Entry point `SyzAgentDxeEntryPoint`:
  1. Locate `EFI_QEMU_FW_CFG_PROTOCOL` (or use `QemuFwCfgLib` directly).
  2. Read `opt/syz/program_addr` and `opt/syz/program_size`.
  3. Map the ivshmem PCI BAR with `gDS->AddMemorySpace` if not already
     present, get a HVA pointer.
  4. Loop forever:
     - Spin on a "go" flag in shared memory (host writes it).
     - Parse the program: `(u32 ncalls, struct syz_edk2_call calls[])`.
     - Dispatch using a long `if/else if` chain — same reasoning as
       SYZOS [docs/syzos.md §4](syzos.md#the-dispatch-loop-guest_main):
       a switch can be lowered to a `.rodata` jump table that we cannot
       guarantee is in the active memory map after `gBS->ExitBootServices`.
     - For each call, marshal arguments out of the program buffer and call
       the corresponding `gBS->...` / `gRT->...` / protocol entry. Capture
       the return EFI_STATUS and any out-arguments into the result page.
     - Set the "done" flag.
- An EFI_EXCEPTION_CALLBACK installed via
  `EFI_DEBUG_SUPPORT_PROTOCOL.RegisterExceptionCallback` translates a CPU
  exception into a "panic" record in shared memory + a debug-con printout
  before re-raising.

`SyzAgentDxe` must be careful about every call it dispatches — many UEFI
APIs take pointers, and we are taking those pointers from a fuzzer-controlled
buffer. The dispatcher copies pointer-typed arguments into agent-owned scratch
pages first, exactly like `prog` does on the host. Failing to do so will turn
"the firmware crashed because we mutated arguments wrong" into "the firmware
crashed because we let it dereference a fuzzer-controlled pointer", which
defeats the point.

#### 4.2.2 SyzCoverLib — coverage runtime

`OvmfPkg/Library/SyzCoverLib/SyzCoverLib.inf`, `SanitizerCovTracePc.c`.
Implements:

```c
VOID EFIAPI __sanitizer_cov_trace_pc_guard_init(UINT32 *Start, UINT32 *Stop);
VOID EFIAPI __sanitizer_cov_trace_pc_guard(UINT32 *Guard);
```

`__sanitizer_cov_trace_pc_guard` does the equivalent of what
[executor/executor_test.h:37](../executor/executor_test.h#L37) does: read
the return address, push it into the ring buffer in the ivshmem page. The
function itself must be marked `__attribute__((no_sanitize("coverage")))` or
the equivalent EDK2-friendly attribute, otherwise it will recurse into
itself and stack-overflow on the first call. (BaseLib functions used by it
must also be excluded — easiest done by linking the smallest possible subset
or by reimplementing the few primitives needed inline.)

#### 4.2.3 OvmfPkg DSC/FDF integration

`OvmfPkg/OvmfPkgX64.dsc` and `.fdf` get a new conditional `!if $(SYZ_AGENT)`
block that:

- Adds `SyzCoverLib` as the `NULL` library instance to every DXE driver
  (`MdeModulePkg`, `OvmfPkg`, `NetworkPkg`, …) we want to instrument. The
  `NULL` library mechanism is the standard EDK2 way to inject code into all
  modules without source changes.
- Adds `SyzAgentDxe` as a DXE driver in the `[Components]` and FV.
- Sets `BUILD_TARGETS = NOOPT` and per-module `MSFT/GCC` `BuildOptions` to
  disable LTO (LTO interacts poorly with sanitizer-coverage on EDK2's
  unusual link model).
- Excludes the SEC, ResetVector, and PEI modules from instrumentation by
  *not* adding `SyzCoverLib` to them and by setting
  `MODULE_TYPE.SEC` / `PEI_CORE` / `PEIM` overrides.

#### 4.2.4 Toolchain definition

A new toolchain tag `GCC5SYZ` in
[BaseTools/Conf/tools_def.template](../../edk2/BaseTools/Conf/tools_def.template)
that inherits `GCC5` and appends:

```
*_GCC5SYZ_X64_CC_FLAGS = DEF(GCC_X64_CC_FLAGS) -O0 -fno-discard-value-names
*_GCC5SYZ_X64_CC_FLAGS = DEF(GCC_X64_CC_FLAGS) -fsanitize-coverage=trace-pc-guard
```

(Exact concatenation depends on EDK2's flag-merging order; check existing
GCC5 definitions before mirroring them.) The new tag is what `pkg/build/edk2.go`
passes to `build -t GCC5SYZ`. Do not modify the existing `GCC5` tag —
upstream EDK2 unit-tests use it.

---

## 5. Walk-through of one fuzzing iteration

To make sure all the moving parts agree, here is a single iteration end-to-end.

1. `syz-manager` sees a free VM slot, picks an input from the corpus, mutates
   it via the existing `prog` package code paths (which know nothing about
   EDK2 — they just see a single `syz_edk2_run_program(prog ...)` call with
   a `varlen` array of `syz_edk2_call` union variants).
2. `syz-manager` forwards the binary `exec` form of the program to
   `syz-executor` over the existing flatrpc channel.
3. `syz-executor` (running on the Linux host, NOT inside QEMU — because of
   `HostFuzzer: true`) decodes the `exec` form and calls the single
   pseudo-syscall handler `syz_edk2_run_program` defined in
   `executor/common_edk2.h`.
4. The handler memcpy's the program bytes into the ivshmem page at a fixed
   offset, writes the size, sets the doorbell flag.
5. `SyzAgentDxe` (which has been spinning on the doorbell since boot)
   notices the flag, reads the program, dispatches each `syz_edk2_call`:
   e.g. `gRT->SetVariable(L"foo", &SomeGuid, attr, size, data)`.
6. Each call's coverage trickles into the cover ring via
   `__sanitizer_cov_trace_pc_guard`, which simply writes the PC into the
   guest's view of the same ivshmem page (`mmio` to RAM, no traps).
7. After all calls complete, `SyzAgentDxe` writes the "done" flag and the
   per-call result codes.
8. The host handler returns to `syz-executor`, which drains the cover ring
   into its per-call cover slot, which `syz-manager` ingests through the
   normal `flatrpc` reply path.
9. If during dispatch a CPU exception fires, the OVMF exception handler
   prints to debug-con (port 0x402) and then resets the VM via the
   `ResetSystem` runtime service — `vm/qemu` sees the serial output, parses
   it via `pkg/report/edk2.go`, attributes the crash to the program, and
   tells the VM dispatcher to discard this VM and bring up a fresh one.

Nothing in this loop is novel for syzkaller above the description level —
everything is reusing existing infrastructure. The novelty is entirely in
the guest agent and the coverage transport, both of which are isolated to
files that do not exist yet.

---

## 6. Limitations of this approach

Read this section before committing to the design — most of these are
fundamental, not implementation bugs.

### 6.1 Coverage range is fixed at firmware build time

OVMF code is a contiguous `[TextStart, TextEnd)` blob in flash. KASLR doesn't
exist for firmware (technically PE/COFF images can be relocated by the DXE
core, but the relocation slide is determined at boot, not per-call). This is
fine for `pkg/cover` — but it means coverage from option ROMs loaded out of
PCI BARs at runtime, or from images dispatched out of an FV in a pflash
update, will not be correctly attributed unless we track relocations. **First
release does not handle relocated images**; we will only count coverage in
modules statically linked into the OVMF binary.

### 6.2 Per-program isolation is best-effort

§3.5 covers this. Without snapshot fuzzing, mutations to global state
(installed protocols, allocated pool, modified PCD, modified variables)
*persist across programs*. This means:

- Bugs that depend on a specific *combination* of programs (a "context bug")
  will be triggerable, which is good.
- Bugs that depend on a *clean* state will be missed unless the corpus
  happens to start clean, which is bad.
- The corpus distribution will drift toward programs that operate on the
  state previous programs have created — this is a known property of
  long-running stateful fuzzers and is acceptable, but it is not the same
  as Linux fuzzing where each `syz-executor` fork starts fresh.

Snapshot fuzzing (option 2 in §3.5) fixes this. Plan to land it in a
follow-up; it is not required for the first release but the agent must be
written so the snapshot point is well-defined (just before the dispatch
loop's spin).

### 6.3 No SEC/PEI coverage in v1

Sanitizer coverage requires writable memory and a stack. SEC runs out of
flash with no DRAM controller initialized; PEI runs in temporary RAM (CAR
mode on Intel) where heap allocation is restricted. Instrumenting these is
non-trivial and the bug surface there is small (a few thousand lines, mostly
identical across boots). **v1 instruments only DXE/SMM-equivalent modules.**

### 6.4 SMM is hard to reach

SMM handlers are gated behind specific software SMIs (port 0xB2 / 0xB3) and
many of them check the source CPL. We can drive them from a DXE-context
agent, but the SMM handler's view of memory is different from DXE's (SMRAM
is locked down). This means SMM handlers are reachable but their coverage
counters live in SMRAM and *cannot* be flushed to ivshmem from inside SMM
without a custom escape hatch. **v1 reaches SMM but does not collect
coverage from it.** This still has value because the SMM handler crash will
be observable as an exception during the SMI return.

### 6.5 GUIDs in syzlang

Syzlang has no native 128-bit or 16-byte type. UEFI is built around GUIDs
(`EFI_GUID` is a 16-byte struct). Workarounds:

- Define each GUID we care about as a `string` literal in syzlang, and have
  the agent translate string-to-bytes via a lookup table compiled into
  `SyzAgentDxe`. Limits the fuzzer to known GUIDs but is the easiest start.
- Add a `[binary "..."]` constant form, generalising the existing
  `` `deadbeef` `` hex literal in
  [docs/syscall_descriptions_syntax.md §string](syscall_descriptions_syntax.md).
  This change would have to land in `pkg/ast` and `pkg/compiler` and is a
  general improvement.
- Add a 16-byte `int128` to syzlang. Avoid this — it ripples through the
  entire `prog` package.

Recommend the "GUID lookup table" approach for v1 with a TODO to revisit.

### 6.6 No system call numbers / no fork server

`SyscallNumbers: false` and `ExecutorUsesForkServer: false` together mean
that the executor's per-program ramp-up is more expensive than on Linux.
This is not unique to EDK2 — Fuchsia and Windows are in the same boat —
but we should set expectations: **single-VM throughput will be on the
order of tens of programs per second**, not the thousands that
syz-executor sees on Linux. Snapshot fuzzing lifts the ceiling, but a
non-snapshot mode is the baseline.

### 6.7 Variable store side-effects across programs

`SetVariable` writes to the OVMF variable store, which is the
`OVMF_VARS.fd` pflash file. If we don't restore that file between VMs we
will pollute it indefinitely and eventually exceed the pflash size, causing
*every* subsequent boot to hang in PEI variable init. The QEMU launcher in
`pkg/build/edk2.go` must `cp OVMF_VARS.template.fd OVMF_VARS.fd` per VM
launch. The `vm/qemu` `EfiVarsDevice` Config field already supports this
pattern; we just need to wire the per-instance copy through.

### 6.8 OVMF is one of many EDK2 platforms

This proposal targets OVMF/X64 only. ARM64 (`ArmVirtPkg/ArmVirtQemu`) uses a
different boot flow and a different toolchain. The design generalises in the
obvious way — add `edk2/arm64` to `targets.go`, port `SyzAgentDxe` to AArch64
(no fundamental changes), parse a different OVMF binary path — but it is
explicitly out of scope for v1 and the descriptions in `sys/edk2/` should be
written portably (avoid x86-specific protocol GUIDs in `sys/edk2/edk2.txt`,
push them into `sys/edk2/edk2_amd64.txt` like `sys/linux/dev_kvm_amd64.txt`).

### 6.9 Reproduction and minimization are slower

`pkg/repro` works by running candidate programs repeatedly. With snapshot
fuzzing this is fine; without it, every reproduction step is a full VM
reboot. We should mark all `syz_edk2_call` variants that mutate persistent
state with `no_minimize` per
[docs/syscall_descriptions_syntax.md](syscall_descriptions_syntax.md), to
keep `syz-repro` from chasing red herrings.

### 6.10 We will need to maintain an EDK2 fork

The agent + coverage runtime + DSC integration are 1k–2k lines of EDK2 C
code that upstream is unlikely to take. Plan: maintain a small patch series
on top of an EDK2 release tag, refresh it quarterly, document the rebase
procedure in `docs/edk2_design.md` so it's not folklore. Treat the EDK2
patch series as a tracked dependency of the syzkaller `edk2` target the
same way `syz-cluster` tracks its dependencies.

### 6.11 No symbolizer for PE/COFF .debug split files (today)

`pkg/symbolizer` was written assuming `vmlinux` (a single ELF with full
DWARF). EDK2 produces one `.efi` per module plus a sibling `.debug` ELF
with symbols only. We need to either teach `pkg/symbolizer` to consume an
"index of `.debug` files + load addresses" or build a unified ELF post-
build. The "build a unified ELF" approach is simpler and lives entirely in
`pkg/build/edk2.go`; recommend that.

---

## 7. Code style and conventions

To match the rest of the syzkaller codebase, all new code must follow these
rules. They are derived from
[docs/contributing.md](contributing.md),
[GEMINI.md](../GEMINI.md), and the patterns visible in the existing
per-OS targets — they are not negotiable for landing the patches.

### 7.1 Go

- **License header.** Every new `.go` file starts with the standard
  two-line header, with the *current year*. Pattern:
  ```go
  // Copyright 2026 syzkaller project authors. All rights reserved.
  // Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
  ```
  See [sys/freebsd/init.go](../sys/freebsd/init.go) for the canonical
  example.
- **Package layout.** One package per OS under `sys/`, one builder per OS
  under `pkg/build/`, one report parser per OS under `pkg/report/`. Do not
  introduce a `pkg/edk2/` umbrella package — syzkaller does not have one
  for any other target and adding one for EDK2 would invite drift.
- **Imports.** Group as `stdlib` / `github.com/google/syzkaller/...` /
  third-party, separated by blank lines. `goimports` ordering is enforced
  by `make format`.
- **Formatting.** `make format` runs `gofmt` and `clang-format`. Run it
  before every commit. CI will reject any patch with diffs.
- **Linting.** `make lint` (which delegates to `golangci-lint run ./...`).
  Fix all warnings. The project's `.golangci.yml` is the source of truth.
- **Tests.** Use `github.com/stretchr/testify/require` for assertions, not
  hand-written `if got != want { t.Fatal(...) }`. Per
  [GEMINI.md](../GEMINI.md), this is mandatory for new tests.
- **Naming.** Match existing per-OS files. The constant for the OS in
  [sys/targets/targets.go](../sys/targets/targets.go) is `EDK2`, the
  string is `"edk2"` (all-lowercase), the package directory is `sys/edk2/`,
  the executor header is `executor/executor_edk2.h`.
- **Error messages.** Lowercase, no trailing punctuation, prefer wrapping
  with `fmt.Errorf("doing X: %w", err)`. Look at
  [pkg/build/freebsd.go](../pkg/build/freebsd.go) for examples.
- **No new dependencies.** Do not pull in new Go modules to parse PE/COFF.
  `pkg/build/edk2.go` should shell out to `objcopy`/`llvm-objcopy` or
  reuse `debug/pe` from the standard library.

### 7.2 syzlang descriptions

- **Header comment.** Same two-line header as Go files but with `#`:
  ```
  # Copyright 2026 syzkaller project authors. All rights reserved.
  # Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
  ```
  See [sys/linux/dev_kvm_amd64.txt](../sys/linux/dev_kvm_amd64.txt).
- **Names match upstream.** Per
  [docs/syscall_descriptions.md §names](syscall_descriptions.md#names),
  prefer the EDK2 names verbatim. `EFI_VARIABLE_NON_VOLATILE` is the flag
  name, not `NV_VAR`. The pseudo-syscall variants follow the
  `syz_edk2_<verb>_<noun>` convention; sub-call IDs follow the `<scope>_<verb>`
  convention (`set_variable`, `locate_protocol`).
- **Declaration order.** Per
  [docs/syscall_descriptions.md §order](syscall_descriptions.md#order),
  syscalls and the top-level `syz_edk2_call` union come first; supporting
  structs and `flags` declarations follow. Do not declare in C-style
  bottom-up order.
- **Flags vs enums.** Use `flags` for both bitmask attributes
  (`EFI_VARIABLE_*`) and exclusive enums
  (`EFI_ALLOCATE_TYPE`). Per
  [docs/syscall_descriptions.md §flags](syscall_descriptions.md#flags),
  let the fuzzer figure out which one it is — do not pre-classify by hand.
- **One file per subsystem.** `variable.txt`, `protocol.txt`,
  `network.txt`, `hii.txt`, mirroring the `dev_*.txt` / subsystem split
  in `sys/linux/`. Architecture-specific types go into `*_amd64.txt`.
- **`*.const` files.** Generated by `syz-extract`, **committed** alongside
  the matching `*.txt` in the same commit. CI checks consistency.
- **`make generate`** must produce no diffs after touching descriptions.
- **No "interesting" magic values.** Per
  [docs/syscall_descriptions.md §values](syscall_descriptions.md#values),
  do *not* manually add `0xffffffff` / `INT_MAX` / `-1` to flag sets.
  Trust the fuzzer's existing magic-value logic.
- **Resources.** Every UEFI handle (`EFI_HANDLE`, `EFI_EVENT`,
  `EFI_FILE_HANDLE`) becomes a `resource`. Producer/consumer pairs are
  marked with `out`/`in` directions on struct fields, exactly as
  [docs/syscall_descriptions_syntax.md §resources](syscall_descriptions_syntax.md#resources)
  describes.

### 7.3 C / C++ (executor side)

- **License header.** Same two-line header.
- **Style.** EDK2's `BaseTools/Scripts/uncrustify.cfg` for in-tree EDK2 C
  files. **For files in `executor/` (which are syzkaller, not EDK2)**,
  follow the existing executor style: `clang-format` per the syzkaller
  `.clang-format`, `snake_case` for functions, `kCamelCase` for constants.
  Look at [executor/common_kvm_amd64.h](../executor/common_kvm_amd64.h)
  for the canonical conventions.
- **`#if` guards.** Pseudo-syscall implementations are guarded with
  `#if SYZ_EXECUTOR || __NR_syz_edk2_run_program`, matching the SYZOS
  pattern. This is mandatory — `syz-prog2c` relies on it to produce
  minimal C reproducers.
- **No `<stdio.h>` / `<stdlib.h>` in pseudo-syscalls.** They must compile
  inside `syz-prog2c`-generated standalone C files, which means using only
  `printf`-via-`debug` and the helpers already in
  [executor/common.h](../executor/common.h).
- **Header-only when possible.** SYZOS is header-only for exactly the
  `syz-prog2c` reason described in
  [docs/syzos.md §source-organization](syzos.md#source-organization--guest_code).
  Apply the same rule to anything that needs to appear in C reproducers.

### 7.4 EDK2-side C (SyzAgentDxe, SyzCoverLib)

This code lives in EDK2, not syzkaller, so it follows EDK2 conventions —
not syzkaller conventions:

- **EDK2 license header** (`/** @file ... SPDX-License-Identifier:
  BSD-2-Clause-Patent **/`).
- **EDK2 type names**: `UINTN`, `UINT64`, `EFI_STATUS`, `BOOLEAN`,
  `IN`/`OUT`/`OPTIONAL` parameter annotations.
- **EDK2 naming**: `PascalCase` for functions and locals (yes, locals),
  `gFooBar` for module globals, no Hungarian prefixes.
- **EDK2 calling convention**: `EFIAPI` on every entry point.
- **Run `BaseTools/Scripts/PatchCheck.py`** before submitting upstream-style
  patches.
- **No CRT / no libc** — only `BaseLib`, `BaseMemoryLib`, `DebugLib`,
  `UefiBootServicesTableLib`, `UefiRuntimeServicesTableLib`, `PcdLib`. If
  you reach for `memcpy`, you mean `CopyMem`.

The executor C code (`executor/executor_edk2.h`) is *not* EDK2 code — it
runs on the Linux host side of the boundary — so it follows syzkaller C
style, not EDK2 style. Don't mix them in the same file.

### 7.5 Commit messages

Per [docs/contributing.md §commits](contributing.md):

- `dir/path: short description` (no leading capital, no trailing dot).
- 120 char limit.
- One logical change per commit. Split:
  - `sys/targets: add edk2 OS`
  - `sys/edk2: initial syzlang descriptions`
  - `executor/edk2: add executor harness`
  - `pkg/build: add edk2 builder`
  - `pkg/report: add edk2 crash parser`
  - `vm/qemu: support edk2/amd64 archConfig`
  - `docs/edk2: usage and design documentation`
- `*.const` files committed in the same commit as their `*.txt`.

### 7.6 Documentation

- A user-facing setup doc at [docs/edk2/setup.md](edk2/setup.md) **NEW**,
  patterned on [docs/freebsd/README.md](freebsd/README.md) /
  [docs/windows/README.md](windows/README.md). It explains how to fetch
  EDK2, apply the SyzAgent patch series, build OVMF with `GCC5SYZ`, and
  point `syz-manager` at the resulting flash images.
- An entry in the top-level [README.md](../README.md) under "Supported
  OSes" listing `EDK2`.
- This design document (you're reading it) stays as `docs/edk2_design.md`.

---

## 8. Open questions

Things the design *could* answer differently and that should be discussed
on `syzkaller@googlegroups.com` before coding starts:

1. **Sanitizer coverage flavour.** `trace-pc-guard` was chosen for
   simplicity (one PC per edge, fixed slot). `trace-pc` is simpler still
   but loses some accuracy. Decide before writing `SyzCoverLib`.
2. **fw_cfg vs ivshmem-doorbell vs debug exit.** fw_cfg is the easiest to
   wire in but is not bidirectional in the obvious way. ivshmem with a
   doorbell MSI is more flexible. Pick one before writing the agent
   transport layer.
3. **Should `SyzAgentDxe` be upstreamed to OvmfPkg behind a build flag, or
   live in a fork?** If upstream is willing, this saves the rebase tax in
   §6.10. Worth opening a discussion on edk2-devel before committing.
4. **Snapshot fuzzing on day 1, or day N?** Day 1 doubles the implementation
   cost but produces a much more useful product. Day N keeps the first
   patch series small.
5. **Which subsystems get descriptions first?** Recommend starting with
   variable services + HII, since both have a long history of CVEs and
   relatively self-contained APIs. Network stack is much higher value per
   bug but requires more setup state.

---

## 9. Effort sketch (informal)

Not a schedule — a rough relative weight, in the spirit of helping
reviewers understand which parts dominate.

| Component | Relative size | Risk |
| --- | --- | --- |
| `sys/targets`, `sys/edk2/init.go`, makefile wiring | small | low |
| `sys/edk2/*.txt` initial descriptions (variable + memory + protocol) | medium | low |
| `executor/executor_edk2.h` + `executor/common_edk2.h` | small | medium (transport correctness) |
| `pkg/build/edk2.go` | medium | medium (EDK2 build is fragile) |
| `pkg/report/edk2.go` + tests | small | low |
| `vm/qemu` archConfig + pflash wiring | small | low |
| `OvmfPkg/SyzAgentDxe` + `OvmfPkg/Library/SyzCoverLib` (in EDK2 fork) | large | high |
| Snapshot fuzzing integration | medium | high |
| Symbolizer support for split `.debug` files | small | medium |
| docs (setup, design, README entry) | small | low |

The single biggest risk item is the EDK2 agent. Everything on the syzkaller
side reuses well-trodden machinery; everything on the EDK2 side is in code
paths that nobody else has written for, so expect surprises (e.g., the
DXE memory allocator behaving badly under coverage instrumentation, or
exception handling not surviving the dispatch loop's stack frame).

---

## 10. Summary

EDK2 fits cleanly into syzkaller's existing target model **if and only if**
we treat OVMF the way SYZOS treats KVM: build a small in-firmware agent
that interprets a fuzzer-generated command sequence, expose the command
sequence as one pseudo-syscall in syzlang, run `syz-executor` on the host
in `HostFuzzer` mode, and pipe coverage out via shared memory. Everything
else — manager, mutator, corpus, repro, web UI — works without
modification, because it does not know what an OS is, only what a
`prog.Target` is.

The hard parts are not in syzkaller. They are:

- the EDK2 agent's correctness under arbitrary fuzzer-generated inputs,
- the coverage instrumentation surviving an environment without libc,
- per-program state isolation (which we punt to snapshot fuzzing),
- and maintaining an EDK2 patch set against an upstream that ships fast.

None of those are blockers; they are work. The design above is intended to
make all of that work *additive* — no existing target is touched, no
existing test changes behaviour, and the patch series can land
incrementally:

1. Land the empty target (compiles, generates an empty `gen/edk2_amd64.go`).
2. Land the executor harness against a pre-built OVMF + SyzAgent (no
   builder yet — point at a path).
3. Land `pkg/build/edk2.go`.
4. Add subsystems to `sys/edk2/*.txt` one PR at a time.
5. Land snapshot fuzzing.
6. Generalise to ARM64.

Each step is reviewable in isolation and produces something demonstrably
better than the step before.
