# Bug Injection Catalog — EDK2 Fuzzer Validation

Every handler category gets one planted bug, reachable **via the existing
grammar** (no new syscalls required). Each bug is gated by the runtime
PCD `PcdSyzBugsDispatchInject` (default FALSE). When TRUE, the fuzzer
becomes a validator: the suite passes only when every planted bug is
surfaced by KASan/UBSan/MMIOCS.

Each trip-wire is keyed on a "magic" value the grammar can produce. The
fuzzer's mutator will discover magics within a few thousand programs; a
seed corpus (`seeds/plant-*`) pre-plants every magic so validation runs
in seconds rather than hours.

| # | Category    | Handler                       | Trip magic                          | Planted bug class            | Sanitizer expected |
|---|-------------|-------------------------------|-------------------------------------|------------------------------|--------------------|
| 1 | memory      | `HandleCopyMem`               | `SrcOff==0xDEAD`                    | heap-OOB read                | KASan heap-OOB     |
| 2 | memory      | `HandleAsanPoison`            | `Length==0xBEEF`                    | heap-use-after-free          | KASan UAF          |
| 3 | memory      | `HandleSetMem`                | `Offset==0xCAFE`                    | heap-OOB write               | KASan heap-OOB     |
| 4 | variable    | `HandleSetVariable`           | `NameSize==0xABCD`                  | stack-OOB read from scratch  | KASan stack-OOB    |
| 5 | event       | `HandleCreateEvent`           | `NotifyTpl==0xFACE`                 | divide-by-zero in handler    | UBSan div-0        |
| 6 | image       | `HandleLoadImage`             | `Length==0xBAD0`                    | integer overflow NumPages*PgSize | UBSan mul-ov / KASan heap-OOB |
| 7 | protocol    | `HandleLocateProtocol`        | `ProtocolIdx==0xDEADC0DE`           | NULL dereference             | UBSan null / KASan NULL |
| 8 | block-io    | `HandleBlockIoReadBlocks`     | `BufferSize==0xF00D`                | shadowed-stack OOB           | KASan stack-OOB    |
| 9 | pci-io      | `HandlePciIoMemWrite`         | `Count==0x1337` *(pending)*          | shift-out-of-bounds          | UBSan shift        |
| 10| network     | `HandleIp4Transmit`           | `BufferSize==0xFEED` *(pending)*     | heap-OOB read (hdr parse)    | KASan heap-OOB     |
| 11| graphics    | `HandleGopBlt`                | `Width==251`                         | mul-overflow Width*Height    | UBSan mul-ov       |
| 12| hii         | `HandleHiiNewPackageList`     | `PackageSize==509`                   | heap-OOB read past header    | KASan heap-OOB     |
| 13| smbios      | `HandleSmbiosAdd`             | (unchanged — already TP from §1)     | heap-OOB `GetSmbiosStructureSize` | KASan heap-OOB |
| 14| smi         | `HandleSmmCommunicate`        | `MessageLen==509`                    | stack-OOB write              | KASan stack-OOB    |
| 15| cpuio       | `HandleCpuIo` (MMIO write)    | `Address==0xDEADBEEFULL`             | MMIOCS constraint violation  | MMIOCS enforce     |
| 16| acpi        | `HandleAcpiInstallTable`      | `Length==0xDEED` *(pending)*         | heap-OOB read                | KASan heap-OOB     |
| 17| crypto      | `HandleHash2Hash`             | `DataLength==0xFADE` (64222)         | stack-OOB read               | KASan stack-OOB    |
| 18| console     | `HandleTextOutOutputString`   | `StringSize==126`                    | heap-use-after-free          | KASan UAF          |
| 19| devicepath  | `HandleDevicePathFromText`    | `TextSize==0xDEAF` *(pending)*       | heap-OOB read                | KASan heap-OOB     |
| 20| file        | `HandleFileRead`              | `Offset==0xDEEDBEEF` *(pending)*     | heap-OOB write (dst)         | KASan heap-OOB     |

**Magic revisions (grammar-bound tripwires)** — rows 11, 12, 14, 18 use
smaller magics so the grammar's type constraints don't block reachability.
`gop_blt.width` is bounded `int32[1:256]`, `hii_new_package_list.package_size`
is a `bytesize[data]` where `data` is `array[int8, 4:512]`,
`smm_communicate.message_len` is `int32[0:512]`, and `text_out_output_string.string_size`
is `bytesize[string, int16]` where `string` is `array[int16, 1:64]` (max 128 bytes).
Within these ranges the magics (251, 509, 509, 126) are unique enough that
spurious hits are rare but possible; in the INJECT=FALSE production build
the tripwire code is compiled out entirely, so there are no spurious hits
where it matters.

## Implementation shape

Each trip-wire is three lines inside its handler, compiled out when
`FeaturePcdGet(PcdSyzBugsDispatchInject)` is FALSE:

```c
if (FeaturePcdGet (PcdSyzBugsDispatchInject) && P->Offset == 0xDEADCAFE) {
  SyzBugsLibTriggerHeapOobRead ();  // from new SyzBugsLib
}
```

`SyzBugsLib` exposes one function per bug class:
- `SyzBugsLibTriggerHeapOobRead()`
- `SyzBugsLibTriggerHeapOobWrite()`
- `SyzBugsLibTriggerHeapUaf()`
- `SyzBugsLibTriggerStackOobRead()`
- `SyzBugsLibTriggerStackOobWrite()`
- `SyzBugsLibTriggerDivByZero()`
- `SyzBugsLibTriggerMulOverflow()`
- `SyzBugsLibTriggerShiftOutOfBounds()`
- `SyzBugsLibTriggerNullDeref()`
- `SyzBugsLibTriggerMmiocsViolation()`

Each function takes `VOLATILE` locals and indirect indices so the
compiler can't optimise the bug away.

## Seed corpus

Twenty seed programs under
`tools/syz-edk2-fuzz/seeds/plant-*.prog`, one per row above. Each trips
exactly its planted bug.

## Validation protocol

1. Build OVMF with `-D SYZ_BUGS_DISPATCH_INJECT=TRUE`.
2. Run `syz-manager -config …-validate.cfg` for **5 minutes**.
3. Expect all 20 unique crash signatures to appear in `workdir/crashes/`.
4. Any missing bug ⇒ either the sanitizer isn't catching that class or
   the mutator can't reach the magic. In either case that row is red
   until fixed.
5. Rebuild with `-D SYZ_BUGS_DISPATCH_INJECT=FALSE` for production.

## Why this design

- **Zero boot-time noise**: all tripwires gated by PCD, compiled out.
- **Grammar-level verification**: each bug is reachable via an existing
  syscall variant, so a "red" row is direct evidence the fuzzer can't
  reach that handler or the sanitizer doesn't catch that class.
- **Deterministic seeds**: validation is 5 minutes, not 5 hours.
- **Per-category coverage**: 20 categories × 10 bug classes = matrix
  that proves the whole stack end-to-end.
