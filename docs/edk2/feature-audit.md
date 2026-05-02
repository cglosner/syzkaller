# syzkaller feature audit — edk2 target

State of every syzkaller component when targeting edk2/amd64. Updated
after the Phase 2 + sanitizer-canary verification work.

## Tooling matrix

| Tool             | Status   | Notes                                                                                                                                                          |
|------------------|----------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `syz-manager`    | ✅       | TCG-snapshot mode (`tcg_snapshot:true` in cfg) drives the campaigns. r1–r7 all used it. Web UI on `localhost:56755` works while running.                       |
| `syz-executor`   | ✅       | Native build via `clang++ -I. -I/tmp/flatbuffers-23.5.26/include` (the upstream syz-env Docker rebuild clobbers this — see *Known issue: build pipeline*).      |
| `syz-execprog`   | ✅       | Builds with Go 1.25; replays a `.prog` file via the local executor at ~250 progs/sec.                                                                          |
| `syz-mutate`     | ✅       | Mutates programs against an edk2 corpus.db.                                                                                                                    |
| `syz-prog2c`     | ✅       | Generates a C reproducer from a textual `.prog` (uses syscall stubs; `syz_edk2_run_program` becomes an opaque call).                                           |
| `syz-db`         | ✅       | pack / unpack / merge / print all work for edk2 target. Used to build corpus from `plant-seeds/` and `chain-seeds/`.                                            |
| `syz-extract`    | ✅       | Extracts constants from EDK2 headers into `sys/edk2/edk2.txt.const` (run after grammar changes).                                                                |
| `syz-sysgen`     | ✅       | Regenerates Go bindings from the textual descriptions. Required when `edk2.txt` changes — bumps the syscall-description hash, requires executor rebuild.       |
| `syz-fmt`        | ✅       | Formats `edk2.txt`.                                                                                                                                            |
| `syz-repro`      | ⚠️       | Builds, but autoreproduction needs a manager.cfg + execution.log. Untested for edk2 specifically — TCG-snapshot path may not retain enough state for replay.    |
| Web UI `/cover`  | ⚠️       | Renders. Source-line annotation depends on per-module ELF DWARF. The `pkg/report/edk2.go` symbolizer can resolve module+offset but the cover page maps PCs from a single ELF — for OVMF you'd need to wire up `addr2line` over each `.dll` separately. (Documented in `docs/edk2/README.md`.) |
| Coverage feedback | ✅ trace-pc only | `trace-pc-guard` and `trace-cmp` both hang TCG boot. Per-module gate would fix it, see "Future work" below.                                                  |
| Hub integration  | ❌       | edk2 isn't an upstream-supported target; no hub-side schema exists.                                                                                            |

## Resource types declared

| Resource       | Used by                                                                                       | Slot count |
|----------------|----------------------------------------------------------------------------------------------|------------|
| `edk2_alloc_slot`  | `allocate_pool` → `copy_mem` / `set_mem` / `free_pool` / `calculate_crc32` / `asan_*` etc. | 11 (0–8, 15, 31) |
| `edk2_event_slot`  | `create_event` → `signal_event` / `wait_for_event` / `set_timer` / `close_event`           | 9          |
| `edk2_file_slot`   | `file_open` → `file_read` / `file_write` / `file_get_info` / `file_close` / `file_delete`  | 8          |
| `edk2_image_slot`  | `load_image` → `start_image` / `unload_image`                                              | 8          |

Adding new resource chains: add `resource <name>[int32]: 0, 1, …` to
`sys/edk2/edk2.txt`, mark the producing syscall variant returns it
(suffix `<resource>` after the parens), then any consumer can take it
typed. Re-run `bin/syz-sysgen`; rebuild executor + manager with matching
`GIT_REVISION` and the new syscall-description hash.

## Crash report flow

```
firmware -> [debugcon 0x402]  -> debug.log -> manager scans
firmware -> [COM1 0x3F8]      -> serial.log -> manager also scans
manager  -> pkg/report/edk2.go regex / addr2line -> Title + GuiltyFile
manager  -> dedupe by (Title hash) -> workdir/crashes/<hash>/report*
```

`pkg/report/edk2.go` handles:
- ASan reports (`==ERROR: AddressSanitizer: …`)
- UBSan reports (`ASAN MEMORY ACCESS check fail! __ubsan_handle_*`)
- X64 exception dumps (vector + register state)
- MMIOCS reports (`==ERROR: MMIOCS: …`)
- Module load lines (`Loading driver at 0x… EntryPoint=… <module>.efi`)
- PC-to-module symbolization via fwsnap-discover.log fallback

Any crash that fits one of those patterns gets a clean Title + GuiltyFile.

## Build-pipeline known issues

1. **GIT_REVISION + SYZ_REVISION mismatch.** Manager + executor each
   embed a `GIT_REVISION` (set via `-ldflags`) and a `SYZ_REVISION`
   (the syscall-descriptions hash from `executor/defs.h`). Both must
   match exactly or the manager refuses to talk to the executor:
   ```
   FATAL: aborting RPC server: mismatching manager/executor system call
          descriptions: <hash-A> vs <hash-B>
   ```
   When you run `syz-sysgen` to update the bindings, the SYZ_REVISION
   bumps. The executor then needs a clean rebuild via:
   ```
   clang++ -I. -I/tmp/flatbuffers-23.5.26/include \
       -DGOOS_edk2=1 -DGOARCH_amd64=1 -DHOSTGOOS_linux=1 \
       -DGIT_REVISION="\"$(git rev-parse HEAD)+\"" \
       -O2 -std=c++17 -pthread \
       -o bin/edk2_amd64/syz-executor executor/executor.cc
   ```
   Manager + execprog must be rebuilt with the executor's GIT_REVISION
   via `-ldflags`. Standard `make all TARGETOS=edk2` handles this for
   you (when run inside `tools/syz-env`), but the `syz-env` Docker
   rebuilds clobber the native executor (glibc 2.38 mismatch on the
   host). Native build is the workaround.

2. **flatbuffers version pinned to 23.5.26.** `pkg/flatrpc/flatrpc.h`
   has a `static_assert(FLATBUFFERS_VERSION_MAJOR == 23 && _MINOR == 5
   && _REVISION == 26)`. Newer flatbuffers from `go.mod` (currently
   25.12.19) won't satisfy. Cache the 23.5.26 headers under
   `/tmp/flatbuffers-23.5.26/` (we have a copy from
   `https://github.com/google/flatbuffers/archive/refs/tags/v23.5.26.tar.gz`).

3. **go.mod uses `tool` blocks (Go 1.24+).** Pre-1.24 toolchains
   choke. We use Go 1.25 from the upstream binary release at
   `/tmp/go25/go/bin/go`. The system `go` is 1.18.

4. **Executor rebuild bumps SYZ_REVISION but the cached
   `Conf/target.txt` may still point at the previous build.** Wipe
   `Build/OvmfX64/NOOPT_GCC5/X64/...` (or just delete `executor/defs.h`
   and re-run sysgen) if the manager keeps rejecting on hash.

## Sanitizer & coverage flags wired into DSC

| Flag                          | Default | Purpose                                                                                          |
|-------------------------------|--------:|--------------------------------------------------------------------------------------------------|
| `SYZ_AGENT_ENABLE`            | FALSE   | Pulls in `SyzAgentDxe` + `SyzCoverLib`. Must be TRUE for fuzzing.                                |
| `ASAN_ENABLE`                 | FALSE   | Builds the `AsanLibFull` runtime + reserves the DRAM shadow at `0x30000000`.                     |
| `ASAN_INSTRUMENT`             | FALSE   | Applies `-fsanitize=kernel-address` wildcard to DXE/UEFI/SMM driver classes.                     |
| `UBSAN_INSTRUMENT`            | FALSE   | Applies `-fsanitize=undefined,pointer-overflow` wildcard.                                         |
| `SYZ_BUGS_DISPATCH_INJECT`    | FALSE   | Compiles the 15 dispatcher tripwires that gate on magic input values.                            |
| `SYZ_BUGS_BOOT_CANARY`        | FALSE   | Includes `SyzBugsDxe` in the FV. At DXE entry it runs the full ASan/UBSan canary sweep.           |
| `MMIOCS_ENFORCE`              | FALSE   | When TRUE, MMIOCS rejects undeclared addresses BEFORE the CPU access (suppresses fuzzer noise).   |
| `SYZ_FAULT_GUARD`             | FALSE   | When TRUE, installs the `#DE`/`#UD`/`#GP`/`#PF` trampoline. FALSE for max bug visibility.        |
| `SMM_REQUIRE`                 | FALSE   | Enables SMM build (PiSmmCpuDxe + SmmBufValLib). Currently untested under TCG-snapshot.            |

## Recommended config matrix

| Goal                                         | Build flags                                                                     |
|----------------------------------------------|---------------------------------------------------------------------------------|
| **Production bug-hunt**                      | `SYZ_AGENT=TRUE ASAN_ENABLE=TRUE ASAN_INSTRUMENT=TRUE UBSAN_INSTRUMENT=TRUE MMIOCS_ENFORCE=TRUE SYZ_FAULT_GUARD=TRUE SYZ_BUGS_DISPATCH_INJECT=FALSE SYZ_BUGS_BOOT_CANARY=FALSE` |
| **Tripwire validation (proving plumbing)**   | flip `SYZ_BUGS_DISPATCH_INJECT=TRUE` and `SYZ_FAULT_GUARD=FALSE`                 |
| **Sanitizer canary (one-shot)**              | flip `SYZ_BUGS_BOOT_CANARY=TRUE`                                                |
| **SMM bug hunt (future)**                    | flip `SMM_REQUIRE=TRUE` (also requires SMM_REQUIRE-aware fwsnap region map)     |

## Future work

1. **Per-module trace-cmp.** Currently rejected at the DSC level
   because TCG boot wedges. A SyzAgent-armed gate (only emit cmp
   callbacks when fuzz mode is active, not during DXE init) would
   work. Patches welcome to `OvmfPkg/Library/SyzCoverLib/SyzCoverTrace.c`.
2. **`/cover` source view.** Wire per-module addr2line into the manager's
   `pkg/cover/` pipeline; currently it expects one ELF + DWARF root.
3. **KVM-mode fwsnap.** The plugin assumes single-thread RR TCG. KVM
   would 5–10× the throughput.
4. **`syz-repro` validation.** Verify automated reproduction works
   end-to-end against the AuthVar CFI bug (round-3 finding).
5. **Hub registration.** No upstream hub schema knows about edk2/amd64;
   register one when this lands upstream.
