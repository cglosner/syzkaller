# edk2 grammar — walkthrough

A short reference for the three questions that come up most often when
debugging the edk2 fuzz target.

## 1. Where is the grammar?

The syzkaller-side description is split across three files. They MUST stay
in lockstep with the EDK2-side dispatcher header.

| file | role |
|---|---|
| [`sys/edk2/edk2.txt`](../sys/edk2/edk2.txt) | the syzlang description: every Service / Protocol the agent dispatches and the corresponding payload struct |
| [`sys/edk2/edk2.txt.const`](../sys/edk2/edk2.txt.const) | hand-rolled constant table (`syz-extract` doesn't run against EDK2 headers) — `EDK2_PROTO_*`, `EDK2_VAR_NS_*`, `EFI_VARIABLE_*`, `EVT_*`, `TPL_*`, `EfiBootServicesData`, … |
| [`sys/edk2/init.go`](../sys/edk2/init.go) | minimal target-init shim that registers the edk2/amd64 target with the prog package |
| [`OvmfPkg/SyzAgentDxe/SyzAgentDxe.h`](../../../edk2-syzkaller/OvmfPkg/SyzAgentDxe/SyzAgentDxe.h) (in the edk2 fork) | C-side `SYZ_EDK2_API_*` enum + every payload `typedef struct {} SYZ_EDK2_*_PAYLOAD;` — the dispatcher casts wire bytes to these |
| [`OvmfPkg/SyzAgentDxe/SyzAgentDispatch.c`](../../../edk2-syzkaller/OvmfPkg/SyzAgentDxe/SyzAgentDispatch.c) | one `Handle*` function per API id, each calling the real EDK2 service / protocol entry point |

### Services and protocols covered by the current grammar

The full list of `syz_edk2_call` union variants in
[`sys/edk2/edk2.txt`](../sys/edk2/edk2.txt) (line 270 onward):

| group | API id | call | EDK2 API exercised |
|---|---:|---|---|
| baseline | 1 | `nop` | (no-op echo) |
| Variable Services | 100 | `set_variable` | `gRT->SetVariable` |
| | 101 | `get_variable` | `gRT->GetVariable` |
| | 102 | `query_variable_info` | `gRT->QueryVariableInfo` |
| | 103 | `get_next_variable_name` | `gRT->GetNextVariableName` |
| Memory Services | 200 | `allocate_pool` | `gBS->AllocatePool` |
| | 201 | `free_pool` | `gBS->FreePool` |
| | 202 | `allocate_pages` | `gBS->AllocatePages` |
| | 203 | `free_pages` | `gBS->FreePages` |
| | 204 | `copy_mem` | `gBS->CopyMem` |
| | 205 | `set_mem` | `gBS->SetMem` |
| | 206 | `calculate_crc32` | `gBS->CalculateCrc32` |
| Time / Misc | 230 | `get_time` | `gRT->GetTime` |
| | 231 | `set_time` | `gRT->SetTime` |
| | 232 | `stall` | `gBS->Stall` |
| | 233 | `set_watchdog_timer` | `gBS->SetWatchdogTimer` |
| | 234 | `get_monotonic_count` | `gBS->GetNextMonotonicCount` |
| Event / TPL | 250 | `create_event` | `gBS->CreateEvent` |
| | 251 | `close_event` | `gBS->CloseEvent` |
| | 252 | `signal_event` | `gBS->SignalEvent` |
| | 253 | `raise_tpl` | `gBS->RaiseTPL` / `RestoreTPL` |
| Protocol Services | 300 | `locate_protocol` | `gBS->LocateProtocol` |
| | 301 | `locate_handle_buffer` | `gBS->LocateHandleBuffer` |
| | 302 | `install_config_table` | `gBS->InstallConfigurationTable` |
| HII | 400 | `hii_new_package_list` | `EFI_HII_DATABASE_PROTOCOL.NewPackageList` |
| | 401 | `hii_remove_package_list` | `EFI_HII_DATABASE_PROTOCOL.RemovePackageList` |
| ASan | 500 | `asan_poison_alloc` | `AsanSyzPoison` |
| | 501 | `asan_unpoison_alloc` | `AsanSyzUnpoison` |
| | 502 | `asan_report_alloc` | `AsanSyzReport` |

The protocol identifiers passed to `locate_protocol` /
`locate_handle_buffer` are *symbolic* — the syzlang flag
`edk2_protocol_id` carries an enum, and the agent maps each value back to
the real `EFI_GUID` via `gSyzEdk2ProtocolTable[]` in
`SyzAgentDispatch.c`. The currently-listed targets:

- `EDK2_PROTO_LOADED_IMAGE` → `gEfiLoadedImageProtocolGuid`
- `EDK2_PROTO_DEVICE_PATH` → `gEfiDevicePathProtocolGuid`
- `EDK2_PROTO_BLOCK_IO` → `gEfiBlockIoProtocolGuid`
- `EDK2_PROTO_DISK_IO` → `gEfiDiskIoProtocolGuid`
- `EDK2_PROTO_SIMPLE_FS` → `gEfiSimpleFileSystemProtocolGuid`
- `EDK2_PROTO_SIMPLE_TEXT_OUT` → `gEfiSimpleTextOutProtocolGuid`
- `EDK2_PROTO_SIMPLE_NETWORK` → `gEfiSimpleNetworkProtocolGuid`
- `EDK2_PROTO_SERIAL_IO` → `gEfiSerialIoProtocolGuid`
- `EDK2_PROTO_HII_DATABASE` → `gEfiHiiDatabaseProtocolGuid`
- `EDK2_PROTO_HII_STRING` → `gEfiHiiStringProtocolGuid`
- `EDK2_PROTO_HII_FONT` → `gEfiHiiFontProtocolGuid`

The same scheme applies to variable namespaces (`EDK2_VAR_NS_*` →
`EFI_GLOBAL_VARIABLE`, `EFI_IMAGE_SECURITY_DATABASE`, …) so the fuzzer
never has to send raw GUIDs across the wire.

## 2. What does a generated program look like?

`tools/syz-edk2-fuzz/dump_program.go` (build-tag `ignore` so it doesn't
ship in `bin/`) prints the syzlang AST and the wire-format hex of one
generated program. With seed=2:

```text
$ ./tools/syz-env go run tools/syz-edk2-fuzz/dump_program.go 2

================  syzlang serialized program ================
syz_edk2_run_program(&(0x7f0000000000)={0x53595a45, 0x9, [
    @nop={0x1, 0x10, {0x8}},
    @get_monotonic_count={0xea, 0x10, {0xfffffffffffffffd}},
    @locate_protocol={0x12c, 0xc, {0xc9}},
    @set_watchdog_timer={0xe9, 0x18, {0xe7, 0xd418}},
    @free_pages={0xcb, 0xc, {0x3}},
    @raise_tpl={0xfd, 0xc, {0x10}},
    @install_config_table={0x12e, 0x14, {0x65, 0x3da7}},
    @locate_protocol={0x12c, 0xc, {0x65}},
    @nop={0x1, 0x10, {0x2}}
]})
```

The same program walked as a `*prog.Prog` tree:

```text
call: syz_edk2_run_program
  PointerArg name=ptr res=*prog.GroupArg
    GroupArg name=edk2_program len=3
      ConstArg name=const val=1398364741 size=4    # SYZE magic
      ConstArg name=len    val=9          size=4    # ncalls
      GroupArg name=array  len=9                    # array of syz_edk2_call
        UnionArg name=syz_edk2_call opt=syz_edk2_api[1, edk2_api_nop_payload]
          GroupArg len=3
            ConstArg val=1   size=4   # SyzEdk2ApiNop
            ConstArg val=16  size=4   # bytesize[parent]
            GroupArg name=edk2_api_nop_payload
              ConstArg val=8 size=8   # cookie
        UnionArg name=syz_edk2_call opt=syz_edk2_api[234, edk2_api_get_monotonic_count]
          ...
```

And the same program after the host-side walker
([grammar.go::walkSyzEdk2RunProgram](../tools/syz-edk2-fuzz/grammar.go)) flattens it to wire bytes:

```text
[off=0x0000] call_id=1   size=16    01 00 00 00 10 00 00 00 08 00 00 00 00 00 00 00
[off=0x0010] call_id=234 size=16    ea 00 00 00 10 00 00 00 fd ff ff ff ff ff ff ff
[off=0x0020] call_id=300 size=12    2c 01 00 00 0c 00 00 00 c9 00 00 00
[off=0x002c] call_id=233 size=24    e9 00 00 00 18 00 00 00 e7 00 00 00 18 d4 00 00
                                    00 00 00 00 00 00 00 00
[off=0x0044] call_id=203 size=12    cb 00 00 00 0c 00 00 00 03 00 00 00
[off=0x0050] call_id=253 size=12    fd 00 00 00 0c 00 00 00 10 00 00 00
[off=0x005c] call_id=302 size=20    2e 01 00 00 14 00 00 00 65 00 00 00 a7 3d 00 00
                                    00 00 00 00
[off=0x0070] call_id=300 size=12    2c 01 00 00 0c 00 00 00 65 00 00 00
[off=0x007c] call_id=1   size=16    01 00 00 00 10 00 00 00 02 00 00 00 00 00 00 00
```

The C side of one of those records — say `call_id=233`, `set_watchdog_timer` — is
the dispatch handler in [`OvmfPkg/SyzAgentDxe/SyzAgentDispatch.c`](../../../edk2-syzkaller/OvmfPkg/SyzAgentDxe/SyzAgentDispatch.c):

```c
typedef struct {
  UINT32  TimeoutSecs;   // 0xE7  = 231 seconds
  UINT64  Code;          // 0xD418
  UINT32  DataSize;      // 0
} SYZ_EDK2_SET_WATCHDOG_PAYLOAD;

STATIC EFI_STATUS
HandleSetWatchdogTimer (CONST UINT8 *Payload, UINTN PayloadSize)
{
  CONST SYZ_EDK2_SET_WATCHDOG_PAYLOAD *P = (CONST SYZ_EDK2_SET_WATCHDOG_PAYLOAD *)Payload;
  return gBS->SetWatchdogTimer (P->TimeoutSecs, P->Code, P->DataSize, NULL);
}
```

so byte-for-byte the 24-byte record at `[off=0x002c]` lays out as:

```
e9 00 00 00     UINT32 Call           = 233 (SyzEdk2ApiSetWatchdogTimer)
18 00 00 00     UINT32 Size           = 0x18 = 24
e7 00 00 00     UINT32 TimeoutSecs    = 231
18 d4 00 00 00 00 00 00   UINT64 Code = 0xD418
00 00 00 00     UINT32 DataSize       = 0
```

That's exactly the input the dispatcher's `HandleSetWatchdogTimer` will
read when this program is poked across.

## 3. How does a program get from host syz-edk2-fuzz into the SyzAgentDxe dispatcher?

A 256 MiB ivshmem-plain region is the entire I/O channel. The host
mmaps the backing file; QEMU maps the same pages into the guest as PCI
BAR2 of the `0x1AF4:0x1110` device. The first 0x2000 bytes are the
SyzAgent control region, laid out in
[`OvmfPkg/SyzAgentDxe/SyzAgentDxe.h`](../../../edk2-syzkaller/OvmfPkg/SyzAgentDxe/SyzAgentDxe.h):

```
[0x0000]  UINT32 magic       ('SYZE' = 0x53595A45)
[0x0004]  UINT32 ncalls      (1..32)
[0x0008]  ... packed array of SYZ_EDK2_CALL records
[0x1000]  UINT32 host_seq    (host -> guest doorbell)
[0x1004]  UINT32 guest_seq   (guest -> host ack)
[0x1008]  UINT32 guest_status (0 = OK, non-zero = agent error)
[0x2000]  UINT32 PcCount; UINT64 Pcs[PcCount]   (sanitizer-coverage ring)
```

The doorbell + ack handshake is intentionally trivial — both sides poll
on `host_seq` / `guest_seq`. There's no IRQ. We don't need one because
the host side of the loop (`syz-edk2-fuzz`) is event-driven on the
ack and the guest side runs out of a 1ms periodic timer.

### Host side — [`tools/syz-edk2-fuzz/main.go::pokeAgent`](../tools/syz-edk2-fuzz/main.go)

```go
func pokeAgent(data []byte, prog *program, timeout time.Duration) bool {
    writeU32(data, edk2OffMagic, edk2Magic)         // SYZE
    writeU32(data, edk2OffNcalls, uint32(prog.NumCalls))
    copy(data[edk2OffCalls:edk2OffCalls+uint32(len(prog.Wire))], prog.Wire)
    writeU32(data, edk2OffGuestStatus, 0)
    cur := readU32(data, edk2OffHostSeq)
    want := cur + 1
    writeU32(data, edk2OffHostSeq, want)            // ring the doorbell
    deadline := time.Now().Add(timeout)
    for time.Now().Before(deadline) {
        if readU32(data, edk2OffGuestSeq) == want { // poll for ack
            return true
        }
        time.Sleep(50 * time.Microsecond)
    }
    return false
}
```

### Guest side — [`OvmfPkg/SyzAgentDxe/SyzAgentDxe.c::SyzAgentDispatchOne`](../../../edk2-syzkaller/OvmfPkg/SyzAgentDxe/SyzAgentDxe.c)

```c
// Runs from a 1 ms periodic timer set up in SyzAgentOnPciIo.
STATIC VOID EFIAPI SyzAgentDispatchOne (VOID) {
    UINT32 HostSeq;
    if (!SyzEdk2TransportPoll (&HostSeq)) {            // host_seq != LastSeq?
        return;
    }
    gSyzEdk2Agent.LastSeq = HostSeq;

    // Pull the entire program record into a local buffer so the rest
    // of the dispatch path can use plain pointer arithmetic, no matter
    // whether the BAR is identity-mapped or we have to go through
    // PciIo->Mem.Read.
    SyzEdk2TransportReadBytes (0, mProgramBuffer, sizeof (mProgramBuffer));
    Magic    = *(CONST UINT32 *)(mProgramBuffer + SYZ_EDK2_OFF_MAGIC);
    NumCalls = *(CONST UINT32 *)(mProgramBuffer + SYZ_EDK2_OFF_NCALLS);

    if (Magic != SYZ_EDK2_PROGRAM_MAGIC) { SyzEdk2TransportAck (1); return; }
    if (NumCalls == 0 || NumCalls > SYZ_EDK2_MAX_CALLS) { SyzEdk2TransportAck (2); return; }

    SyzCoverReset ();                                  // clear cover ring
    DispatchStatus = SyzEdk2Dispatch (
        mProgramBuffer + SYZ_EDK2_OFF_CALLS,
        SYZ_EDK2_MAX_PROGRAM_BYTES,
        NumCalls);

    SyzEdk2TransportAck (DispatchStatus == EFI_SUCCESS ? 0 : 3);
}
```

`SyzEdk2Dispatch` walks the wire payload one (call_id, size, payload)
record at a time, looks the call_id up in a switch statement, and
hands the payload bytes to the matching `Handle*` function. Each
handler casts the payload to the typed struct and calls the real EDK2
boot/runtime/protocol entry point.

`SyzEdk2TransportAck` writes `guest_status` first, then bumps
`guest_seq`, with a `MemoryFence ()` between the two so the host
never observes a stale status with a fresh sequence. The dispatcher
also drains the agent's per-program cover ring into the host's
`pcSet` map via [`drainCoverage`](../tools/syz-edk2-fuzz/main.go).

### Wire transport — direct CPU map vs PciIo fallback

`SyzEdk2TransportInit` (in
[`SyzAgentTransport.c`](../../../edk2-syzkaller/OvmfPkg/SyzAgentDxe/SyzAgentTransport.c))
discovers the ivshmem device, enables `EFI_PCI_IO_ATTRIBUTE_MEMORY` on
its command register, and sniffs the BAR mapping by writing a magic at
offset 0x1FFC via `PciIo->Mem.Write` and reading it back through the
direct CPU pointer. If the two agree (the firmware page tables
identity-map the 64-bit MMIO window the host bridge advertised) the
agent uses plain volatile loads/stores; if they don't, it routes every
transport access through `PciIo->Mem.{Read,Write}`. ASan instrumentation
issues plain CPU stores, so if `mUseBarIo` is `TRUE` the asan shadow is
unavailable and stays deactivated.

### End-to-end timing

A typical asan-instrumented OvmfPkgX64 build spends ~40 s in DXE bring-up
(PciBus enumeration is the long pole) and then enters the dispatch loop.
A 30 s grammar campaign then comfortably acks ~1000 programs / ~10 000
calls and produces ~1900 unique sanitizer-coverage PCs.
