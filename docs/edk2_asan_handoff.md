# Plan: handing off the EDK2 ASan shadow region to a Linux kernel guest

## What we have today

The `syzkaller-edk2` fork ships with these moving parts:

1. **`AsanLibFull`** — full asan runtime in EDK2, NULL-injected into every
   instrumented DXE/SMM module. Provides `__asan_load*`/`__asan_store*` /
   `__asan_register_globals` / `__asan_set_shadow_*` and the matching
   `__ubsan_handle_*` family. The deactivation guards in `Asan.c` keep
   the shadow mutators a no-op until the shadow region is wired up.

2. **`gAsanShadowReadyProtocolGuid`** — a late-binding rendezvous
   protocol declared in
   [`MdeModulePkg/MdeModulePkg.dec`](../../../edk2-syzkaller/MdeModulePkg/MdeModulePkg.dec)
   carrying an `ASAN_SHADOW_INFO { ShadowMemoryStart; ShadowMemorySize; }`
   interface. AsanLibFull's constructor registers a notify on it, and
   the notify callback patches the per-module shadow globals so each
   instance can flip from "deactivated" to "active" without recompiling
   the firmware.

3. **A 256 MiB ivshmem-plain BAR**. The first 2 MiB is the SyzAgent
   control region (program payload + doorbell + cover ring). The
   remaining 254 MiB lives at offset `SYZ_EDK2_OFF_SHADOW = 0x200000`
   and is the address-sanitizer shadow window. With `SHADOW_SCALE=3`
   that covers ~2 GiB of trackable physical memory — enough for the
   full DXE address range OVMF Q35 hands out.

4. **`SyzAgentDxe`** discovers the BAR after PciIo notify, runs an
   identity-mapping probe, stashes the shadow base into
   `gSyzEdk2Agent.AsanShadowBase / Size`, and is *ready* to install
   the protocol — but the install is deliberately deferred (see the
   "Why deferred" section in
   [`SyzAgentDxe.c`](../../../edk2-syzkaller/OvmfPkg/SyzAgentDxe/SyzAgentDxe.c)).

The same shadow region is therefore visible to both:

- the **firmware side** as plain CPU loads/stores against the BAR
  (page tables identity-map the 64-bit MMIO window), and
- the **host side** through `mmap` of the ivshmem backing file at
  offset 0x200000.

We can hand it off to the Linux kernel by giving the kernel a third
window into the same physical pages.

## Goal

Boot a Linux guest on top of OVMF (with `SMM_REQUIRE=TRUE` and the
SyzAgent enabled), have the kernel:

1. discover the ivshmem-plain BAR via PCI;
2. learn the **same** shadow base + size that the firmware was using;
3. plug those values into KASAN's `kasan_init_hw_tags` /
   `KASAN_GENERIC` shadow setup so a single shadow window backs both
   firmware-side and kernel-side checks; and
4. expose a userspace ioctl that fires SMIs (via `outb 0xB2` under
   `iopl(3)`), so the syzkaller `tools/syz-edk2-smi-fuzz` runner can
   exercise SMM handlers from the Linux side and let asan catch any
   write that crosses from non-SMRAM into shadowed buffers.

## Architecture

```
                                   ┌─────────────────────────────────┐
                                   │  syz-edk2-{fuzz,smi-fuzz} (host)│
                                   └──────────────┬──────────────────┘
                                                  │ ivshmem-plain BAR
                                                  │ 256 MiB host file
                       ┌──────────────────────────▼──────────────────┐
                       │  qemu (smm=on) — guest physical memory      │
                       │                                             │
   firmware boot ─────►│  OVMF: SyzAgentDxe + AsanLibFull            │
                       │   ├─ control region [0..0x200000)           │
                       │   └─ asan shadow [0x200000..256M)           │
                       │                                             │
                       │  hand-off via UEFI Configuration Table:     │
                       │      gAsanInfoGuid → ASAN_SHADOW_INFO {     │
                       │           Start = bar_base + 0x200000,      │
                       │           Size  = bar_size - 0x200000 }     │
                       │                                             │
   ExitBootServices ──►│  Linux kernel (early_param("kasan_handoff"))│
                       │   ├─ walks UEFI config tables               │
                       │   ├─ finds ASAN_SHADOW_INFO                 │
                       │   ├─ kasan_install_external_shadow(start)   │
                       │   └─ enables KASAN with handoff offset      │
                       │                                             │
                       │  Linux userspace runner (smi-fuzz/runner):  │
                       │   ├─ ioctl(/dev/kasan-handoff, GET_SHADOW)  │
                       │   ├─ ioctl(/dev/kasan-handoff, FIRE_SMI)    │
                       │   └─ feeds back to host via ivshmem doorbell│
                       └─────────────────────────────────────────────┘
```

## Step-by-step plan

### Step A — produce a UEFI configuration table from SyzAgentDxe (firmware)

In the same place where the agent currently *would* call
`gBS->InstallProtocolInterface(&gAsanShadowReadyProtocolGuid, ...)`,
also call:

```c
static ASAN_SHADOW_INFO mShadowInfo;
mShadowInfo.ShadowMemoryStart = (UINT64)(UINTN)gSyzEdk2Agent.AsanShadowBase;
mShadowInfo.ShadowMemorySize  = (UINT64)gSyzEdk2Agent.AsanShadowSize;
gBS->InstallConfigurationTable (&gAsanInfoGuid, &mShadowInfo);
```

UEFI configuration tables survive `ExitBootServices`. The OS loader sees
them via the EFI System Table that the kernel keeps around. The kernel
can therefore find the shadow region without needing PCI access.

### Step B — Linux: walk the UEFI config tables on early boot

Add a small early-boot helper to `arch/x86/platform/efi/`:

```c
#include <linux/efi.h>
#include <linux/kasan.h>

static const efi_guid_t asan_info_guid = EFI_GUID(
    0xac0634da, 0x320e, 0x4f1d,
    0x8d, 0x0c, 0x2e, 0x99, 0x1e, 0xab, 0xe5, 0xae);

struct asan_shadow_info {
    u64 shadow_start;
    u64 shadow_size;
};

void __init efi_kasan_handoff_init(void)
{
    struct asan_shadow_info *info;
    info = efi_lookup_table(&asan_info_guid);
    if (!info)
        return;
    pr_info("kasan: handoff shadow @ 0x%llx size 0x%llx\n",
            info->shadow_start, info->shadow_size);
    kasan_init_external_shadow(info->shadow_start, info->shadow_size);
}
```

Wire it into `start_kernel()` immediately after `efi_init()` runs (it
already runs before `mm_init()` which is when KASAN normally allocates
its own shadow). The handoff replaces that allocation.

### Step C — Linux: teach KASAN to use an externally-mapped shadow

Mainline KASAN allocates its shadow lazily from vmalloc on x86_64. We
need a `CONFIG_KASAN_EXTERNAL_SHADOW` knob that:

1. accepts a `(start, size)` pair from
   `kasan_init_external_shadow()`;
2. **skips** the normal vmalloc-based shadow allocation in
   `kasan_populate_zero_shadow()` for the range covered by the handoff;
3. installs a fixed `KASAN_SHADOW_OFFSET = handoff_start - (kernel_low_addr >> 3)`
   so `kasan_mem_to_shadow(addr)` lands inside the handoff window for
   addresses the firmware also tracks (i.e. low DRAM that both DXE
   pool and the early kernel page tables live in);
4. ioremaps the handoff range with WRITE_BACK / UC- attributes
   matching what OVMF set on the BAR (already cacheable PMem64).

The math here is the tricky part — the shadow offset needs to be the
same value that OVMF's `mShadowOffset` ended up at, so the
firmware's previous poison bytes are visible to the kernel. Easiest
way to verify: at handoff time, peek at the first cache line of the
shadow window and confirm it matches what the firmware just wrote
(e.g. AsanLibFull poisons module redzones with `kAsanGlobalRedzoneMagic
= 0xf9`).

### Step D — Linux: a thin /dev/kasan-handoff char device

A small char-driver module exposes:

| ioctl | direction | argument | use |
|---|---|---|---|
| `KASAN_HANDOFF_GET_SHADOW` | OUT | `struct {u64 start; u64 size;}` | for the userspace runner to know where the shadow is and verify the firmware's view matches |
| `KASAN_HANDOFF_GET_BAR`    | OUT | `struct {u64 phys; u64 size;}` | physical address of the ivshmem BAR — needed by `mmap(/dev/mem, ...)` so the userspace runner can talk to the host fuzzer over the doorbell |
| `KASAN_HANDOFF_FIRE_SMI`   | IN  | `u8 cmd`       | calls `iopl(3)` once and then issues `outb(cmd, 0xB2)` from kernel context (avoids the userspace runner needing root capabilities) |
| `KASAN_HANDOFF_PRIME_PHYS` | IN  | `struct {u64 addr; u32 len; u8 data[];}` | poke attacker bytes into a physical address using `ioremap_cache` — equivalent to `/dev/mem` writes but allowed under STRICT_DEVMEM |

The driver lives in
`drivers/firmware/syz_edk2_handoff.c` (or out-of-tree if upstreaming
isn't desired).

### Step E — host: make `tools/syz-edk2-smi-fuzz` use the handoff path

Switch the existing `runner.c` (which mmaps `/sys/bus/pci/.../resource2`
and writes `/dev/mem` directly) to talk to the new `/dev/kasan-handoff`
device instead. Same wire format on the ivshmem control region; the
runner just gets:

- the shadow base/size from `KASAN_HANDOFF_GET_SHADOW` so it can
  cross-check what the firmware advertised;
- physical-memory pokes through `KASAN_HANDOFF_PRIME_PHYS` instead of
  `/dev/mem mmap` (lets `CONFIG_STRICT_DEVMEM=y` stay on);
- SMI triggers through `KASAN_HANDOFF_FIRE_SMI` so the runner stops
  needing `iopl(3)`.

## What this buys us

Once Step C is in place, **the kernel and the firmware share a single
asan shadow window**. That means:

- Any write the kernel issues that lands inside a region the firmware
  marked as poisoned (e.g. an SMM communication buffer redzone) will
  trip a KASAN report on the kernel side, *even though* the buffer
  was set up by SMM code we never asked the kernel to instrument.
- Conversely, any SMM handler that reads back from a kernel-side
  buffer will see the kernel's poison bytes — so a callout into a
  freed slab object lights up the firmware's asan check.

Both directions of the SMI callout problem become detectable from a
single asan runtime, with no need to plumb a separate "is this access
allowed" oracle into SMM.

## Risks and open questions

- **Address-arithmetic constraint.** The shadow offset that satisfies
  both `(dxe_addr >> 3) + offset == handoff_window` AND
  `(kernel_addr >> 3) + offset == handoff_window` requires both DXE
  and kernel memory to live in the same low-physical range. With
  `-m 1024` OVMF Q35 they do (DXE pool ~0x3C000000-0x40000000,
  kernel image ~0x01000000+). With `-m 4096` the kernel reaches into
  the high-RAM split and the math doesn't compose; we'd need to grow
  the shadow window or use a per-region offset table.

- **MMIO speed.** ivshmem-plain BARs *should* be plain RAM-backed
  KVM memory slots (no traps), but in our diagnostic runs activating
  asan on certain modules wedged the boot dispatcher — the suspected
  cause is a slow shadow-poison loop running on what KVM is treating
  as MMIO. Before completing Step C, validate this with a tiny
  benchmark: time `Intrinsic_memset(shadow_base, 0, 1MB)` from a
  uninstrumented DXE driver and confirm it's microseconds, not
  seconds. If it isn't, switch the shadow allocation to a normal
  reserved-DRAM region (carved out via `BuildMemoryAllocationHob`
  from PEI) and propagate that base instead.

- **Cache coherency between firmware and kernel writes.** The
  firmware writes its module-redzone bytes during DXE; those writes
  go through the CPU's normal caches. After `ExitBootServices` the
  kernel takes over and may run with different MTRR/PAT attributes
  on the same physical pages. We'll need to either explicitly
  WBINVD before handoff or pick the same caching attribute on both
  sides (`PAT WB` is the safe default, matching what OVMF uses for
  prefetchable PMem64 BARs).

- **SMM comm-buffer alignment.** SMI callouts happen against the
  SMM communication buffer at `gEfiSmmCommunicationProtocolGuid`.
  The fuzzer needs to know the precise address of that buffer so it
  can poison the right bytes. SyzAgentDxe should publish it in the
  same configuration table as the asan shadow info.

## Status / next concrete deliverables

| step | status |
|---|---|
| A. firmware: produce gAsanInfoGuid config table | code already has the data; one extra `gBS->InstallConfigurationTable` call away |
| B. linux: walk config tables, find handoff | requires 1 small patch to `arch/x86/platform/efi/efi.c` |
| C. linux: KASAN_EXTERNAL_SHADOW config | needs a real KASAN patch; the most invasive piece |
| D. linux: /dev/kasan-handoff driver | tiny char-driver, ~200 lines |
| E. host: switch syz-edk2-smi-fuzz runner to ioctls | already-scaffolded `tools/syz-edk2-smi-fuzz/guest/runner.c` just swaps the I/O backend |

The cheapest first step is **A + the host benchmark in the Risks
section** — both can be done inside the existing `syzkaller-edk2`
fork without touching the kernel. If the benchmark says the BAR is
fast enough, we know Step C is unblocked; if not, we move the shadow
to a reserved DRAM region first and the rest of the chain continues
unchanged.
