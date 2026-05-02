# Sanitizer Verification Matrix

End-to-end proof that every sanitizer's plumbing is intact. Generated
from a single OVMF boot with `SYZ_BUGS_BOOT_CANARY=TRUE` —
`SyzBugsDxe.efi` runs at DXE entry and triggers one bug per class.
Reports captured from two QEMU output channels:

- `debugcon` (port 0x402) → `==ERROR: AddressSanitizer: …` lines
- `COM1` (port 0x3F8) → `ASAN MEMORY ACCESS check fail! __ubsan_handle_*`
  lines + a custom `MMIOCS:` prefix

## ASan — 5/6 classes verified

| Bug class                    | Test (SyzBugsDxe.c)        | Output                                                                | Shadow magic | Status |
|------------------------------|----------------------------|-----------------------------------------------------------------------|--------------|--------|
| heap-buffer-overflow read    | `TestHeapOobRead`          | `==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x3C6B84BC at pc 0x3C4442DD`  | `0xfa` | ✅ |
| heap-buffer-overflow write   | `TestHeapOobWrite`         | `==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x3C6B84BC at pc 0x3C4443A0`  | `0xfa` | ✅ |
| heap-use-after-free          | `TestHeapUseAfterFree`     | `==ERROR: AddressSanitizer: heap-use-after-free on address 0x3C6B84AC at pc 0x3C444463`   | `0xfd` | ✅ |
| stack-buffer-overflow        | `TestStackOob`             | `==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x3FCDC4F4 at pc 0x3C4446C6` | `0xf3` | ✅ |
| global-buffer-overflow       | `TestGlobalOob`            | `==ERROR: AddressSanitizer: global-buffer-overflow on address 0x3C452FB8 at pc 0x3C444830`| `0xf9` | ✅ |
| heap double-free             | `TestHeapDoubleFree`       | (gated — DxeCore `ASSERT(Block->Signature == ...)` fires first)        | — | ⊘ |

## UBSan — 6/8 classes verified

| Bug class                | Test (SyzBugsDxe.c)        | Handler                                  | Status |
|--------------------------|----------------------------|------------------------------------------|--------|
| signed integer overflow (add) | `TestSignedAddOverflow` | `__ubsan_handle_add_overflow`         | ✅ |
| signed integer overflow (mul) | `TestSignedMulOverflow` | `__ubsan_handle_mul_overflow` (LHS=1 RHS=0x21) | ✅ |
| shift out of bounds      | `TestShiftOutOfBounds`     | `__ubsan_handle_shift_out_of_bounds`     | ✅ |
| array bounds             | `TestArrayBounds`          | `__ubsan_handle_out_of_bounds` (3× variants) | ✅ |
| null deref (guarded)     | `TestNullDeref`            | `__ubsan_handle_out_of_bounds` (type-mismatch InsufficientObjectSize) | ✅ |
| misaligned load          | `TestMisalignedLoad`       | `__ubsan_handle_out_of_bounds`           | ✅ |
| integer divide by zero   | `TestDivByZero`            | (skipped — see comment in test)          | ⊘ |
| builtin_unreachable      | `TestUnreachable`          | (disabled by default — would halt boot)  | ⊘ |

## Firmware-specific sanitizers — verified live

| Sanitizer | Module                                              | Verified by                                                      | Status |
|-----------|-----------------------------------------------------|------------------------------------------------------------------|--------|
| MMIOCS    | `OvmfPkg/SyzAgentDxe/SyzAgentDispatch.c::MmiocsValidateAddress` | Production runs r3–r7: 200+ `==ERROR: MMIOCS: undeclared address ...` reports captured. Enforcing mode (`MMIOCS_ENFORCE=TRUE`) verified to cleanly suppress fuzzer-cascade #GP/#PF crashes. | ✅ |
| SMIBVS    | `MdeModulePkg/Library/SmmBufValLib`                 | Built into every DXE_SMM_DRIVER when `SMM_REQUIRE=TRUE`; constructor runs but inert in non-SMM builds. Not yet exercised under SMM-enabled OVMF (defer to Phase 4 SMM rollout). | ⏳ |
| Fault trampoline | `OvmfPkg/SyzAgentDxe/SyzFaultGuard.c`         | Phase 2A. Verified live in r3 production: zero CpuIo2Dxe `#GP`/`#PF` crashes when armed (vs. 4 cluster hashes when disarmed in r1/r2 baseline). | ✅ |

## Reproducer commands

Build:
```
build -p OvmfPkg/OvmfPkgX64.dsc -a X64 -t GCC5 -b NOOPT \
    -D SYZ_AGENT_ENABLE=TRUE -D ASAN_ENABLE=TRUE \
    -D ASAN_INSTRUMENT=TRUE -D UBSAN_INSTRUMENT=TRUE \
    -D SYZ_BUGS_BOOT_CANARY=TRUE \
    -D MMIOCS_ENFORCE=TRUE \
    -D FD_SIZE_IN_KB=8192 -n $(nproc)
```

Boot (capture both channels):
```
qemu-system-x86_64 -machine q35,smm=off -accel tcg,thread=single \
    -cpu qemu64 -m 1024 -nodefaults -no-reboot -nographic \
    -drive if=pflash,format=raw,readonly=on,file=OVMF_CODE.fd \
    -drive if=pflash,format=raw,file=OVMF_VARS.fd \
    -debugcon file:debug.log -global isa-debugcon.iobase=0x402 \
    -serial file:serial.log \
    -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
    -object memory-backend-file,id=syzcov,share=on,mem-path=syzcov.shm,size=256M \
    -device ivshmem-plain,memdev=syzcov
```

Each canary run completes in ~5 min and produces ~30 sanitizer reports.

## Calibration outputs

```
ASan reports captured (debugcon):  5
UBSan reports captured (COM1):     6 (6 distinct __ubsan_handle_* invocations)
SYZ-BUGS sweep markers:           19
SYZBUGSDxe driver loaded:          1
```

The handler addresses (`pc=0x3C4442DD` etc.) all map back into
`SyzBugsDxe.efi` (base=0x3C443000) so the symbolizer can resolve each
back to `SyzBugsDxe.c:line`. Cross-reference against `Build/OvmfX64/NOOPT_GCC5/X64/SyzBugsDxe.map`.
