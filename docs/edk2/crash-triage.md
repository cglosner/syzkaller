# EDK2 Fuzzing Crash Triage

Triage of the unique crashes surfaced by the current `syz-manager` + KASan/UBSan +
snapshot-TCG campaign against OVMF. Each group below covers one deduplicated
fault signature, its suspected root cause, classification (true/false positive
or fuzzer-induced), and a concrete remediation.

The campaign is still running, so this is a snapshot; re-run triage before
treating any conclusion as final.

Workdir: `workdir-edk2-fwsnap/crashes/`

| Hash (prefix)  | Title                                                                                         | Count | Class |
|----------------|-----------------------------------------------------------------------------------------------|-------|-------|
| `1cc9d7…` / `7537de…` / `9a65cc…` | heap-buffer-overflow in `SmbiosDxe!GetSmbiosStructureSize`              | 5     | **TP** |
| `c8ac70…` / `1e72ab…` / `51d42…`  | stack-buffer-over/under-flow in `DxeCore!CoreGetNextLocateByProtocol`   | 6     | **FP** (sanitizer) |
| `f18c59…` / `dd06f5…`             | stack-buffer-overflow in `DxeCore!CoreInternalAllocatePool`             | 12    | **FP** (sanitizer) |
| `f2ae2a…`                         | stack-buffer-overflow in `DxeCore!BuildMemoryDescriptor`                | 2     | **FP** (sanitizer) |
| `c62131…` / `b15663…`             | `X64 #GP / #PF` in `CpuIo2Dxe!MmioWrite64`                              | 3     | Fuzzer-induced |
| `91bc78…`                         | `X64 #DE` inside `CpuDxe` (interrupt epilogue)                          | 1     | Fuzzer-induced (state) |
| `49df37…`                         | `X64 #UD` at `RIP=0xC22E` (low memory, control-flow hijack)             | 2     | **TP candidate** |

Total unique hashes: 13. Three fingerprint SmbiosDxe on the same line; three
fingerprint DxeCore's `CoreGetNextLocateByProtocol` at the same instruction
(overflow and underflow variants are the same bug in mirror image). Remove
those duplicates and there are **six distinct signatures**.

---

## 1. SmbiosDxe – heap-buffer-overflow in `GetSmbiosStructureSize`  (TRUE POSITIVE)

**Signature**
```
==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x3C7B018E at pc 0x3CDCB81F
  in SmbiosDxe+0x81f  => GetSmbiosStructureSize at SmbiosDxe.c:196
  in SmbiosDxe+0x406  => GetSmbiosStructureSize at SmbiosDxe.c:197
  in SmbiosDxe+0x6b1  => GetSmbiosStructureSize at SmbiosDxe.c:221
```
`SmbiosDxe.c:196` is the double-NUL terminator walk at the end of every SMBIOS
entry:

```c
FullSize  = Head->Length;
CharInStr = (INT8 *)Head + Head->Length;            // SmbiosDxe.c:189
...
while (*CharInStr != 0 || *(CharInStr+1) != 0) {    // :196 — reads past Head
```

### How the fuzzer gets there
Our dispatch helper in
[OvmfPkg/SyzAgentDxe/SyzAgentDispatch.c:718-754](../../../edk2-syzkaller/OvmfPkg/SyzAgentDxe/SyzAgentDispatch.c#L718-L754)
assembles a record whose **length byte is fuzzer-controlled**:

```c
UINTN TotalSize = 4 + BodySize + 2;              // allocation size
UINT8 *Record = AllocateZeroPool (TotalSize);
Record[0] = P->EntryType;
Record[1] = P->EntryLength;                      // <-- attacker-controlled
CopyMem (Record + 4, P->Body, BodySize);
Smb->Add (Smb, NULL, &Handle, (…) Record);
```
If the fuzzer sets `P->EntryLength > 4 + BodySize`, `CharInStr` starts outside
the allocation and the `while` loop at line 196 immediately reads past the heap
red-zone. KASan catches the first byte; `-fsanitize-recover=address` then lets
the loop keep walking, which produces the fan-out of 50+ follow-up reports at
the same PC (benign noise from the first real OOB).

### Classification: true positive
`GetSmbiosStructureSize` trusts `Head->Length` without cross-checking the
producer's buffer size. EDK2's current threat model expects `Smbios->Add()`
callers to be trusted platform drivers, but the contract isn't defensive:
a single buggy OEM driver, or an attacker who reaches `Add()` through an
OpROM / runtime-variable / capsule path, can cause SmbiosDxe to read
arbitrary adjacent heap.

### Fix
Add a caller-supplied buffer-length parameter (or bound-check `Head->Length`
against a sane ceiling **and** the allocation size where `Add()` copies the
record). Minimum defensive patch at the helper's call site:

```c
if (Record->Length < sizeof (SMBIOS_STRUCTURE) ||
    Record->Length > MaxBufferLen) {
  return EFI_INVALID_PARAMETER;
}
```
A more thorough fix changes the `Smbios->Add` contract to take an explicit
max-record-size argument; this is an API break but correct.

### Fuzzer improvement (optional)
Tighten the grammar so `entry_length` is within the allocation by default, and
add a *separate* variant that intentionally mis-sizes it — that way we can
distinguish honest add calls from adversarial ones in future campaigns.

---

## 2. DxeCore – stack-buffer-over/underflow cluster  (FALSE POSITIVES)

Three signatures share a fingerprint — all fault addresses are on the
**DXE dispatcher stack** at `0x3FCDC140 / 0x3FCDC150 / 0x3FCDC190`, and each
PC corresponds to a **plain load/store through a caller-provided pointer**:

| Hash      | Function / line                                         | Source                                 |
|-----------|---------------------------------------------------------|----------------------------------------|
| `c8ac70…` | `CoreGetNextLocateByProtocol` `Locate.c:399`            | `Link = Position->Position->ForwardLink;` |
| `f18c59…` | `CoreInternalAllocatePool` `Pool.c:244`                 | `*Buffer = NULL;`                      |
| `f2ae2a…` | `BuildMemoryDescriptor` `Gcd.c:1584`                    | `Descriptor->Attributes = Entry->Attributes;` |

Each line writes or reads through a pointer the caller passed in. The pointers
are valid (caller's stack slot), but KASan reports the access as
`stack-buffer-overflow` (or `underflow`) at a stack slot in the DXE
dispatcher's frame that a **different, earlier** ASan-instrumented callee had
poisoned as a red-zone and did not fully unpoison on return.

### Why we're confident it's a sanitizer artefact
1. Fault address is inside the DXE stack (0x3FCDCxxx), not near any allocated
   object.
2. The "overflowing" access is `*Buffer = NULL` or a single-field struct
   store — no arithmetic that could plausibly stray out of bounds.
3. `CoreGetNextLocateByProtocol` appears with both `overflow` and `underflow`
   at the same address (0x3FCDC140 vs 0x3FCDC198), which is how stale
   left/right redzones present when the same slot is reused.
4. The reports occur only **after** a prior `-fsanitize-recover=address` hit
   has already left the shadow dirty (see the SmbiosDxe signature above —
   the call-site logs show SmbiosDxe's OOB always precedes the DxeCore
   stack reports in the same VM run).
5. Several DxeCore functions are compiled with ASan and share one stack with
   callers that are also ASan-instrumented; EDK2 doesn't call
   `__asan_handle_no_return` on the dispatcher's tail, so stale redzones
   persist across callbacks (TPL-dispatched events, signal events, etc.).

### Classification: false positive, sanitizer-interaction
These are not firmware bugs. They're **ghost reports**: the shadow memory in
the dispatcher's stack region is stale after a prior recoverable hit.

### Remediation options (pick one; we recommend #1 for now)

1. **Filter them in the manager.** They cluster tightly by both PC and fault
   address. Add a skip rule in
   [pkg/report/edk2.go](../../pkg/report/edk2.go) that drops
   `stack-buffer-(over|under)flow` reports whose fault address lies inside
   the DXE dispatcher stack range *when* a prior heap/global report was
   recorded in the same boot.

2. **Disable ASan stack instrumentation globally.**
   Remove `--param asan-stack=1` from the OVMF DSC flag block. This loses
   stack-OOB detection entirely but kills this class of noise outright.
   Re-enable later once (3) is in place.

3. **Add explicit unpoison hooks at DXE dispatcher frame boundaries.** Patch
   `CoreDispatcher()` in
   `MdeModulePkg/Core/Dxe/Dispatcher/Dispatcher.c` to call
   `__asan_handle_no_return()` (or equivalent) before handing control to a
   driver entry point. Correct but invasive.

4. **Make ASan non-recoverable.** Drop `-fsanitize-recover=address`; once the
   first bug fires, the VM stops instead of continuing with corrupted shadow.
   Trade-off: we lose the multi-bug-per-run throughput that lets the
   aggregator collect several true positives before snapshot restore.

### Verification plan
Build one OVMF image with `-fno-sanitize=address,alignment` applied only to
`MdeModulePkg/Core/Dxe/*.c` and rerun for 4 h. If the three DxeCore signatures
stop but SmbiosDxe persists, the hypothesis is confirmed.

---

## 3. CpuIo2Dxe – `#GP / #PF` in `MmioWrite64`  (FUZZER-INDUCED, not a bug)

Two hashes, same root cause:
```
#GP   RIP 0x3D65D5FA   MmioWrite64   IoLib.c:416   RDX = 0xC686FEE7797F7D0F
#PF   RIP 0x3D65D2A9   MmioRead*     IoLib.c        CR2 = 0x00000F8000000000
```
Our grammar exposes `cpu_io_mem_read / cpu_io_mem_write / msr_read / msr_write`
with essentially unconstrained address arguments. The fuzzer picks non-canonical
or unmapped physical addresses, and `CpuIo2Dxe` dereferences them as MMIO —
which is precisely the `EFI_CPU_IO2_PROTOCOL` contract (the caller is
responsible for supplying a valid MMIO range). CPU traps as expected.

### Classification: fuzzer-induced
Not a firmware defect. EDK2 is behaving correctly; we're generating inputs the
API documents as the caller's responsibility.

### Fix
Add an MMIO-address allow-list in the grammar. In
[sys/edk2/edk2.txt](../../sys/edk2/edk2.txt), replace the free-form `addr`
on `cpu_io_mem_*` with an enum drawn from a small list of legal MMIO targets:
LAPIC base (`0xFEE00000`), IOAPIC (`0xFEC00000`), HPET (`0xFED00000`), and
whatever BARs we've actually decoded via `pci_rb_io_pci_*`.

Alternatively (and complementary), gate these calls behind our MMIOCS
sanitizer — which is already in place but only consulted *after* the CPU has
already faulted. Move the range check to *before* the
`gBS->LocateProtocol(EFI_CPU_IO2_PROTOCOL)->Mem.Write` call:
[OvmfPkg/SyzAgentDxe/SyzAgentDispatch.c — HandleCpuIo](../../../edk2-syzkaller/OvmfPkg/SyzAgentDxe/SyzAgentDispatch.c).
If `MmiocsValidateAddress()` returns "disallowed", drop the request.

That will eliminate the noise without losing coverage of the happy-path API.

---

## 4. CpuDxe – `#DE` (divide-error) after `text_out_set_attribute` barrage  (FUZZER-INDUCED)

```
X64 Exception Type - 00 (#DE)   RIP 0x3D140D24   CpuDxe.efi
  symbolized as EnableInterrupts @ GccInlinePriv.c:27
```
The symbolized line is misleading — `GccInlinePriv.c:27` is the inline-asm
wrapper for `STI`, which the compiler inlines at many callsites. The real
RIP is inside CpuDxe's default-exception / interrupt epilogue path. What
actually happened is:

1. The preceding test programs executed
   `cpu_io_port_write(port=0xa, width=9, value=…, count=10)` and similar,
   which push data into the DMA controller / chipset register range.
2. Subsequent `text_out_set_attribute` / `text_out_output_string` calls
   invoke console scrolling math in `ConSplitterDxe` / `GraphicsConsoleDxe`.
3. With corrupted console state (rows/cols driven to zero via some port
   write), the scroll-math divides by zero.

No `CpuDxe` bug — the `#DE` is a symptom of state corruption two drivers up.

### Classification: fuzzer-induced, cascading
### Fix
Same remediation as section 3 — constrain port/MMIO targets so that the
fuzzer cannot poison VGA/chipset state it has no business writing. After
that, rerun and verify this hash no longer reappears.

---

## 5. `#UD` at `RIP = 0xC22E` (low memory)  (TRUE-POSITIVE CANDIDATE)

```
X64 Exception Type - 06 (#UD - Invalid Opcode)   RIP 0x000000000000C22E
!!!! Can't find image information. !!!!
```
RIP is **below every firmware module's base** (OVMF modules start at
`0x3B000000`+). Control reached `0xC22E` because something `RET`'d or
`CALL`'d through a corrupted pointer/stack — there is no real code at that
address, hence `#UD`.

The last-executing programs before the fault are a sustained run of
`text_out_set_attribute` calls, plus a single `text_out_set_attribute(0x0)`
(NULL payload). That null-payload dispatch path is the most suspicious —
our dispatch in SyzAgentDxe should reject it before invoking
`gST->ConOut->SetAttribute`, but a bug in the null-check could let a
garbage pointer through.

### Classification: probable true positive, control-flow integrity
This is the single most interesting crash. Control-flow hijack in a DXE
driver with an ASLR-less firmware is directly exploitable. Needs deeper
investigation:

1. Rebuild with `-fno-sanitize-recover=address` so the VM stops on the
   first contaminated shadow event, then reproduce this one.
2. Capture a QEMU monitor `info registers` + `x/100i $rip-0x80` at the
   moment of the fault. (Our dispatch already prints registers; we need
   the *caller* RIP, not the faulting one.)
3. Walk R10 (`0x3B8765AC`) and R14 (`0x3D97BA28`) to identify the driver
   whose callback was in flight; these are typical
   `ConSplitter`/`GraphicsConsole` interface addresses.

### Fix
Once we've localized the caller, the fix is almost certainly in the
SyzAgentDxe NULL-payload path: tighten the sanity checks in the top of
[HandleRunProgram](../../../edk2-syzkaller/OvmfPkg/SyzAgentDxe/SyzAgentDispatch.c)
so that `Payload == NULL` or `PayloadSize < MinForCall` short-circuits
before any protocol dispatch.

---

## Infrastructure noise (not crashes)

Not shown in the table: occasional `SYZFAIL: failed to recv rpc` lines appear
inside every crash log. This is the executor's post-crash tear-down on the
fuzzer side, not a firmware fault; it always appears *after* the
`==ERROR: AddressSanitizer:` line. We can strip it in
[pkg/report/edk2.go](../../pkg/report/edk2.go) during
`Parse()` to keep logs readable. Low priority.

---

## Summary & next actions

1. **Fix SmbiosDxe.** Submit a patch upstream that rejects records whose
   `Length` doesn't match the caller's buffer. This is the one "real" bug in
   the current set.
2. **Kill DxeCore stack-OOB noise.** Apply option (1) from section 2 (manager
   filter) this week; schedule option (3) (dispatcher unpoison) for a
   follow-up once the filter confirms the diagnosis.
3. **Constrain CpuIo / MSR grammar.** Replace free addresses with
   allow-listed ranges. Gate via `MmiocsValidateAddress` *before* the
   dispatch call.
4. **Investigate the `0xC22E` #UD.** Highest-value lead in the set —
   potentially a real control-flow bug. Needs targeted reproduction
   run with recover disabled.
5. **Rerun** for 12+ h with (2) and (3) in place and confirm that only
   SmbiosDxe + the `#UD` reappear.

All patches should be committed separately so we can bisect if the signal
changes.

---

# Round 2 — new crashes since the first pass

Twelve new hashes landed since the first triage. None of them changes the
big picture: every new signature falls into one of the four buckets we
already identified. Below is a per-hash breakdown.

| Hash (prefix) | Title                                                                                 | Count | Class |
|---------------|---------------------------------------------------------------------------------------|-------|-------|
| `2816fb…`     | **heap-use-after-free** in `SmbiosDxe!GetSmbiosStructureSize`                          | 1     | **TP** (same bug as §1) |
| `38f1874…`    | stack-buffer-underflow in `DxeCore!CoreGetNextLocateByProtocol:399`                   | 18    | **FP** (sanitizer, §2) |
| `8a1a9b…`     | stack-buffer-overflow in `DxeCore!CoreGetNextLocateByProtocol:405`                    | 1     | **FP** (sanitizer, §2) |
| `717d03…`     | stack-buffer-underflow in `DxeCore!CoreInternalAllocatePool:244`                      | 4     | **FP** (sanitizer, §2) |
| `9aaaf2…`     | `unknown-crash` in `DxeCore!CoreInternalAllocatePool:244`                             | 1     | **FP** (sanitizer, §2) |
| `27d230…`     | `X64 #DE` in `CpuIo2Dxe!IoWrite32`                                                     | 2     | Fuzzer-induced cascade |
| `ce297c…`     | `X64 #GP` in `CpuIo2Dxe!MmioRead8` (RDX = `0x00090000_0006005C`)                       | 1     | Fuzzer-induced (§3) |
| `4bc3b5…`     | `X64 #DE` in `DxeCore!CoreAllocatePoolI:530`                                           | 1     | Fuzzer-induced cascade |
| `c838fe…`     | `X64 #DE` in `DxeCore!LookupPoolHead:169`                                              | 1     | Fuzzer-induced cascade |
| `900c41…`     | `X64 #DE` in `DxeCore!CoreConvertPagesEx:741`                                          | 1     | Fuzzer-induced cascade |
| `d0d664…`     | `X64 #DE` in `TerminalDxe!TerminalConOutOutputString:209`                              | 1     | Fuzzer-induced cascade |
| `62b1e9…`     | `X64 #DE` in `SyzAgentDxe!SyzFwfuzzTrigger:183`                                        | 1     | Harness bug (investigate) |

## 6. SmbiosDxe – heap-use-after-free  (`2816fb…`)  (TRUE POSITIVE, SAME BUG)

```
==ERROR: AddressSanitizer: heap-use-after-free on address 0x3C7AC19A at pc 0x3CDCB81F
  => GetSmbiosStructureSize at SmbiosDxe.c:196
Trigger: syz_edk2_run_program$cpu_io_port_write
```
This is the SmbiosDxe heap-OOB from §1 aging into a UAF — by the time
`GetSmbiosStructureSize` re-enters (either via `SmbiosGetNext` or the
published table walker), the over-sized internal copy sits in freed heap.
Same root cause, same fix (bound-check `Head->Length` against the
producer's buffer). Treat as a duplicate of §1 for remediation purposes.

## 7. DxeCore stack cluster — four new hashes, same artefact  (FALSE POSITIVES)

New entries:
- `38f1874…` — `CoreGetNextLocateByProtocol:399` **underflow** (18×)
- `8a1a9b…` — `CoreGetNextLocateByProtocol:405` overflow
- `717d03…` — `CoreInternalAllocatePool:244` **underflow** (4×)
- `9aaaf2…` — same line reported as `unknown-crash`

All fault addresses are on the DXE dispatcher stack (`0x3FCDCxxx`), all
faulting lines are innocuous loads/stores through caller-supplied pointers.
Note especially that we're now seeing **both** over- and under-flow reports
at the same instruction (expected when shadow red-zones on *both* sides of
a reused stack slot are stale) and an `unknown-crash` tag which is how
KASan classifies reads of shadow bytes that aren't one of the known
poison values — another hallmark of corrupted shadow state.

**Action**: no change to the §2 remediation plan — the manager-side filter
(§2 option 1) will squash this whole cluster, plus the original three. It
is by far the loudest class in the campaign now (23 of the 25 unique
hashes end up in the "sanitizer artefact" bucket by volume).

## 8. CpuIo2Dxe – new #GP and #DE signatures  (FUZZER-INDUCED, SAME CLASS)

- `ce297c…` — `#GP` in `MmioRead8` with `RDX = 0x00090000_0006005C`.
  Non-canonical MMIO address, same pattern as §3. The top two bits of the
  high dword are set, making this a non-canonical virtual address → `#GP`.
- `27d230…` — `#DE` in `IoWrite32` (`IoLibGcc.c:265`).

For `27d230…` the "PC" is at `IoLibGcc.c:265`, which is the
`FilterAfterIoWrite()` call — a one-line function call with no arithmetic.
`#DE` at that line is impossible in the source, so the faulting instruction
is almost certainly in `FilterAfterIoWrite`'s body (inlined into `IoWrite32`
in NOOPT builds the DWARF range is imprecise at function boundaries). The
preceding program is a long run of `cpu_io_port_write` calls with
fuzzer-selected `Width`/`Count` values; the chipset state that
`FilterAfterIoWrite` reads through has been corrupted.

**Action**: same as §3 — allow-list MMIO/port addresses in the grammar and
gate them through `MmiocsValidateAddress` pre-dispatch. This will
eliminate both of these and is a prerequisite for separating real bugs
from state-corruption cascades.

## 9. DxeCore pool-manager `#DE` triplet  (FUZZER-INDUCED STATE CASCADE)

Three new hashes with `#DE` inside pool-allocator code:

- `4bc3b5…` — `CoreAllocatePoolI` at `Pool.c:530`
- `c838fe…` — `LookupPoolHead` at `Pool.c:169`
- `900c41…` — `CoreConvertPagesEx` at `Page.c:741`

Each symbolized line is trivially non-divisive:

```c
// Pool.c:169 — just an array index
if ((UINT32)MemoryType < EfiMaxMemoryType) {
    return &mPoolHead[MemoryType];
}
```

```c
// Page.c:741 — function-prologue brace
CoreConvertPagesEx (...)
{
    UINT64           NumberOfBytes;
    ...
```

None of these can produce a real `#DE`; the symbolizer is placing the PC
at the nearest DWARF line. What the preceding programs have in common is
heavy use of `@asan_poison_alloc` / `set_mem` / `load_image_pe` with
malformed PE/COFF headers — i.e. the fuzzer is writing into DxeCore's
shadow map and its own pool-metadata via our `set_mem` syscall.

Looking at the triggers more carefully:
```
syz_edk2_run_program$set_mem(... {r0, 0x2a5b, 0x618, 0xf})
```
`set_mem` writes a fill pattern of length `0x618` *after* a previously
fuzzer-controlled offset — and `r0` comes from an earlier `allocate_pool`.
That's the smoking gun: `set_mem` is scribbling past the returned buffer,
corrupting subsequent pool headers. Later allocations hit the corrupted
metadata and crash somewhere deterministic inside `CoreAllocatePoolI` /
`LookupPoolHead` / `CoreConvertPagesEx`, but not with a clean signature.

**Action**: `set_mem` in our grammar should have its `Size` bounded by
the allocation length of `r0`, not a free 16-bit value. In
[sys/edk2/edk2.txt](../../sys/edk2/edk2.txt), change the `Size` field of
`syz_edk2_run_program$set_mem` to an allocation-relative length, or
simply cap it to 4 KB and clear the bit that lets it exceed the buffer.

This alone should eliminate the majority of these cascading `#DE`s.

## 10. TerminalDxe `#DE` at `TerminalConOutOutputString:209`  (`d0d664…`, FUZZER-INDUCED)

```
RIP 0x3C532FBA in TerminalDxe  =>  TerminalConOut.c:209
```
Line 209 is the `This->QueryMode(This, Mode->Mode, &MaxColumn, &MaxRow);`
indirect call. A `#DE` through an indirect call is only possible if the
resolved function pointer lands on an `idiv` with zero — so the fault is
inside `QueryMode`'s body, not at the call. The preceding programs include
`create_event` + `text_out_set_attribute` storms; stored terminal state
(rows/cols) is being driven to zero and the next division-by-width in
`QueryMode` traps.

**Action**: once the MMIO/port allow-list from §3 is in place, this will
go away. If it doesn't, examine `TerminalConOutOutputString` for its
scroll/wrap arithmetic — this is one of the few places where a legitimate
firmware bug (unchecked divisor) could hide.

## 11. SyzAgentDxe `#DE` inside `SyzFwfuzzTrigger`  (`62b1e9…`, HARNESS BUG)

The most interesting of the new crashes: **the fault is in our own
harness**, not firmware. Symbolized at `SyzFwfuzzTrigger.c:183` (function
entry `{` — line-table rounding), module `SyzAgentDxe.efi`, RIP at
module-base + `0xA5AC`.

Register context:
```
RAX=0x0  RCX=0x2  RDX=0xFFFFFFFF  RBX=0x3B86C2AF  RDI=0x3B87A530
R10=0x3B8765AC (==RIP)  R11=0x1F
```
`RDX = 0xFFFFFFFF` after a `DIV` is exactly what you'd expect right before
a trap: `DIV` was about to execute on `RDX:RAX / RCX` = very-large / 2,
which *won't* trap — so the `#DE` is happening mid-calculation elsewhere.
The function offset `0xA5AC` is *not* inside `SyzFwfuzzTrigger` (that
function is near the image entry at `+0xDC9C`); addr2line's DWARF range
for that image is off by several KB. The real site is somewhere in the
dispatch helpers — likely one of the size/count normalisations that
compute `Remaining / Stride` after reading a fuzzer-provided header.

Trigger sequence:
```
set_watchdog_timer({0x118, 0x4})
set_variable_append / cpu_io_port_write
set_variable_delete (malformed ANYBLOB, missing the last byte)
set_watchdog_timer(0x0)          // NULL payload
cpu_io_port_write(width=0xa, count=0xb, port=0x8)
set_variable_delete(ANYBLOB truncated)
```
The truncated `ANYBLOB` variants yield a payload where our dispatcher
reads a declared size > actual remaining — and then divides by a stride
that the grammar lets the fuzzer pick as `0`.

**Action** — harness-side fix, worth doing immediately:

1. Audit dispatcher helpers in
   [OvmfPkg/SyzAgentDxe/SyzAgentDispatch.c](../../../edk2-syzkaller/OvmfPkg/SyzAgentDxe/SyzAgentDispatch.c)
   for any `x / y` or `x % y` where `y` comes from payload bytes. Guard
   each with `if (y == 0) return EFI_INVALID_PARAMETER;` before the op.
2. Reject short / truncated payloads up-front. The present
   `if (PayloadSize < sizeof(SYZ_...))` checks miss the case where the
   declared record length *inside* the payload exceeds the actual size.
   Compare `HeaderLen + DeclaredBodyLen <= PayloadSize` before trusting
   any inner field.

Classify as a **harness bug**, not a firmware finding. It's the reason
we're getting spurious reports blamed on `SyzAgentDxe` in the dashboard.

---

## Updated running action list

Priority-ordered, combining rounds 1 and 2:

1. **(HARNESS)** Fix dispatcher payload bounds + division guards (§11) — one
   afternoon; eliminates one class of false alarms and enables cleaner
   reruns.
2. **(HARNESS)** Bound `set_mem.Size` to the underlying allocation (§9) —
   will clear three cascade hashes (`4bc3b5`, `c838fe`, `900c41`).
3. **(GRAMMAR)** MMIO/port allow-list via `MmiocsValidateAddress`
   pre-dispatch (§3, §8, §10) — clears `c62131`, `b15663`, `27d230`,
   `ce297c`, `91bc78`, `d0d664`.
4. **(TOOLING)** Manager-side filter for DxeCore stack-shadow ghost
   reports on `0x3FCDCxxx` (§2, §7) — clears 7 hashes, 41 occurrences.
5. **(EDK2)** SmbiosDxe length validation (§1, §6) — the only *real*
   firmware bug in the set; upstream patch.
6. **(EDK2)** Investigate the `#UD` at `RIP = 0xC22E` (§5) — the highest-value
   lead; run a targeted reproduction once items 1-3 are in so the signal
   isn't buried in noise.

If items 1–3 land and we rerun for 12 h, we should see the crash
population collapse from 25 hashes to the SmbiosDxe pair and the `#UD` —
i.e. one real bug and one open investigation. That's the state we want
before calling results ready to publish.

