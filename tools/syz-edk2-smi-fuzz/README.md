# syz-edk2-smi-fuzz

A userspace fuzzer that targets **SMI callout** vulnerabilities in EDK2/OVMF
SMM handlers from inside a Linux guest.

## Why this exists

The companion tool `syz-edk2-fuzz` (in `tools/syz-edk2-fuzz/`) drives the
SyzAgentDxe in-firmware dispatcher to fuzz **DXE** Boot/Runtime Services from
the host side. SMM handlers are not reachable from DXE the same way — they
run in System Management Mode in SMRAM, are entered via System Management
Interrupts, and communicate with non-SMM code through a shared communication
buffer + the `EFI_SMM_COMMUNICATION_PROTOCOL` interface.

Many SMM handlers blindly dereference pointers passed in via that
communication buffer — the *SMI callout* class of bugs. To find them you
need an attacker model where:

1. The attacker controls non-SMRAM memory at addresses the SMI handler
   reads (typically the SMM communication buffer plus whatever pointers
   it contains).
2. The attacker can trigger SMIs at will (`outb 0xB2`) with arbitrary
   command bytes.

A Linux guest running on top of OVMF (built with `SMM_REQUIRE=TRUE`) gives
us exactly this attacker model — root in the guest controls non-SMRAM and
can issue port 0xB2 writes through `iopl` / `ioperm`.

## Architecture

```
                ┌──────────────────────────────┐
                │  host: syz-edk2-smi-fuzz     │
                │  ─────────────────────────   │
                │  - boots qemu+OVMF SMM=on    │
                │  - generates SMI command     │
                │    bundles via prog grammar  │
                │    (sys/edk2_smi)            │
                │  - mmaps an ivshmem-plain    │
                │    region as the I/O channel │
                │  - parses guest crashes from │
                │    OVMF debugcon log         │
                └────────────┬─────────────────┘
                             │ ivshmem (256 MiB)
                             │ + serial console
                ┌────────────▼─────────────────┐
                │  guest: minimal Linux        │
                │  ─────────────────────────   │
                │  initramfs runs /init →      │
                │  ./syz-edk2-smi-runner       │
                │   - mmaps /dev/uio0 (ivshmem)│
                │   - reads next SMI bundle    │
                │   - writes attacker payloads │
                │     into /dev/mem at addrs   │
                │     the bundle specifies     │
                │   - iopl(3); outb(cmd, 0xB2) │
                │   - waits for SMI return     │
                │     (auto via iret)          │
                │   - acks via the same shmem  │
                └──────────────────────────────┘
```

The wire format on the ivshmem region mirrors `tools/syz-edk2-fuzz`'s
SyzAgent control region (magic, ncalls, host_seq/guest_seq doorbell) so the
host-side launcher can be a near-clone of `syz-edk2-fuzz`'s main loop, with
a different program generator (`sys/edk2_smi/edk2_smi.txt`) and a different
guest endpoint (Linux runner instead of DXE dispatcher).

## Status

This directory currently contains:

- `main.go` — host-side launcher skeleton (boots qemu, mmaps ivshmem,
  drives the doorbell). Compiles. Generates blind random SMI bundles
  until the syzlang `sys/edk2_smi/` is added.
- `guest/runner.c` — guest-side runner. Reads bundles via the UIO
  interface to the ivshmem device, primes physical memory via /dev/mem,
  issues SMI port writes. Build with `gcc -static`.
- `guest/init.sh` — initramfs init script that loads `uio_pci_generic`
  and execs the runner.

What's intentionally NOT here yet:

- `sys/edk2_smi/edk2_smi.txt` — syzlang descriptions for SMI command
  bundles (command id, communication header, callout-pointer poisoning,
  etc.). Without it the host generates blind random bytes.
- An initramfs build recipe. The guest runner needs to be packaged into
  an initramfs.cpio.gz that the OVMF guest boots from. Use any standard
  buildroot/dracut/mkinitramfs flow you already have.
- SMM-side coverage. The SyzCoverLib runtime in this repo is wired up
  for DXE only. Extending it into SMM is non-trivial: SMM has its own
  memory map, the standard `EVT_NOTIFY_SIGNAL` events don't fire there,
  and `gST` is not the same. For a first cut we run blind and detect
  crashes by parsing the OVMF debug console.

## Running

```sh
# 1. Build OVMF with SMM enabled (and the rest of the SyzAgent flags
#    if you also want DXE-side instrumentation).
cd /path/to/edk2
. edksetup.sh
build -p OvmfPkg/OvmfPkgX64.dsc -a X64 -t GCC5 -b NOOPT \
    -D SMM_REQUIRE=TRUE -D SECURE_BOOT_ENABLE=TRUE

# 2. Build the syzkaller side.
cd /path/to/syzkaller
make
go build -o bin/syz-edk2-smi-fuzz ./tools/syz-edk2-smi-fuzz/

# 3. Build the guest runner statically and pack an initramfs that
#    includes it as /init (or invoked from /init). Example:
gcc -static -O2 -o /tmp/runner \
    tools/syz-edk2-smi-fuzz/guest/runner.c
( cd /tmp && echo runner | cpio -o -H newc | gzip > initrd.img )

# 4. Run the campaign.
./bin/syz-edk2-smi-fuzz \
    -ovmf-code /path/to/OVMF_CODE.fd \
    -ovmf-vars /path/to/OVMF_VARS.fd \
    -kernel /boot/vmlinuz-... \
    -initrd /tmp/initrd.img \
    -shmem /tmp/syz-edk2-smi.shm \
    -duration 10m
```
