#!/bin/sh
# Minimal initramfs init for syz-edk2-smi-fuzz.
# Pack this with /runner (built statically from runner.c) into the
# guest initramfs (e.g. via cpio + gzip):
#
#   echo "init.sh runner" | cpio -o -H newc | gzip > initrd.img
#
# The guest kernel must have CONFIG_DEVMEM=y (and not CONFIG_STRICT_DEVMEM,
# otherwise the runner can't mmap arbitrary physical pages).

set -eu

mount -t proc  none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev 2>/dev/null || true

# Make sure ivshmem-plain BAR2 is exposed via sysfs (it always is for
# the standard pci bus, no special module load needed).

exec /runner
