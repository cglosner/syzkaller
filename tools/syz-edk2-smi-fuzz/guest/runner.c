// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
//
// Guest-side runner for syz-edk2-smi-fuzz.
//
// Build:
//   gcc -static -O2 -Wall -Wextra -o runner runner.c
//
// At runtime, the runner:
//   1. Locates the ivshmem-plain device exposed by QEMU.
//      We use the bind-by-resource path: the BAR2 region of the
//      0x1AF4:0x1110 PCI device shows up as
//      /sys/bus/pci/devices/<bdf>/resource2 — we mmap that file
//      directly. (The traditional UIO route via uio_pci_generic
//      also works; pick whichever your kernel build supports.)
//   2. Spins waiting for host_seq != last_seq.
//   3. Parses the program payload as a sequence of (kind, size, ...)
//      records.
//   4. For each record:
//        kind=1 (SMI_KIND_WRITE_PHYS): write payload bytes to a
//          physical address via /dev/mem mmap.
//        kind=2 (SMI_KIND_OUTB): outb(payload[0], 0xB2) to trigger
//          the SMI. iopl(3) was raised at startup so this is legal
//          for root.
//        kind=3 (SMI_KIND_READ_PHYS): read len bytes from the given
//          phys addr; we discard the data but the read itself is
//          useful as a validity check.
//   5. Writes guest_status (0=ok), then bumps guest_seq to ack.
//
// This whole thing must run AS ROOT and the host must build OVMF with
// SMM_REQUIRE=TRUE so APMC writes actually trap into SMRAM.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/io.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define SMI_MAGIC          0x53595A53u
#define SMI_OFF_MAGIC      0x0000u
#define SMI_OFF_NCALLS     0x0004u
#define SMI_OFF_CALLS      0x0008u
#define SMI_OFF_HOST_SEQ   0x1000u
#define SMI_OFF_GUEST_SEQ  0x1004u
#define SMI_OFF_GUEST_STAT 0x1008u
#define SMI_MAX_CALL_BYTES 0x0FF8u

#define KIND_WRITE_PHYS 1
#define KIND_OUTB       2
#define KIND_READ_PHYS  3

#define APMC_PORT 0xB2

#define IVSHMEM_VID 0x1AF4
#define IVSHMEM_DID 0x1110

static volatile uint8_t *g_shared;
static size_t g_shared_size;
static int g_devmem;

static volatile uint32_t *u32(volatile uint8_t *base, uint32_t off) {
    return (volatile uint32_t *)(base + off);
}

static int find_ivshmem_resource(char *out, size_t outlen) {
    DIR *d = opendir("/sys/bus/pci/devices");
    if (!d) return -1;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char vp[512], dp[512];
        snprintf(vp, sizeof(vp), "/sys/bus/pci/devices/%s/vendor", e->d_name);
        snprintf(dp, sizeof(dp), "/sys/bus/pci/devices/%s/device", e->d_name);
        FILE *fv = fopen(vp, "r"), *fd = fopen(dp, "r");
        if (!fv || !fd) {
            if (fv) fclose(fv);
            if (fd) fclose(fd);
            continue;
        }
        unsigned int vid = 0, did = 0;
        fscanf(fv, "%x", &vid);
        fscanf(fd, "%x", &did);
        fclose(fv);
        fclose(fd);
        if (vid == IVSHMEM_VID && did == IVSHMEM_DID) {
            int n = snprintf(out, outlen,
                             "/sys/bus/pci/devices/%s/resource2", e->d_name);
            if (n < 0 || (size_t)n >= outlen) {
                closedir(d);
                return -1;
            }
            closedir(d);
            return 0;
        }
    }
    closedir(d);
    return -1;
}

static int map_ivshmem(void) {
    char path[256];
    if (find_ivshmem_resource(path, sizeof(path)) != 0) {
        fprintf(stderr, "[smi-runner] no ivshmem device found\n");
        return -1;
    }
    int fd = open(path, O_RDWR | O_SYNC);
    if (fd < 0) {
        fprintf(stderr, "[smi-runner] open %s: %s\n", path, strerror(errno));
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) < 0) {
        fprintf(stderr, "[smi-runner] fstat %s: %s\n", path, strerror(errno));
        close(fd);
        return -1;
    }
    g_shared_size = (size_t)st.st_size;
    void *m = mmap(NULL, g_shared_size,
                   PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED) {
        fprintf(stderr, "[smi-runner] mmap %s: %s\n", path, strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    g_shared = (volatile uint8_t *)m;
    return 0;
}

static int handle_write_phys(const uint8_t *p, size_t n) {
    if (n < 12) return -1;
    uint64_t addr = *(const uint64_t *)(p + 0);
    uint32_t len  = *(const uint32_t *)(p + 8);
    if (12u + len > n) return -1;
    if (len > 0x10000) len = 0x10000;
    off_t pa = (off_t)(addr & ~(off_t)0xFFF);
    size_t map_len = ((addr - pa) + len + 0xFFF) & ~(size_t)0xFFF;
    void *m = mmap(NULL, map_len, PROT_READ | PROT_WRITE,
                   MAP_SHARED, g_devmem, pa);
    if (m == MAP_FAILED) {
        // Probably crossed into a region the kernel marks reserved.
        // Not fatal — the fuzzer will pick a different addr next time.
        return 0;
    }
    memcpy((uint8_t *)m + (addr - pa), p + 12, len);
    munmap(m, map_len);
    return 0;
}

static int handle_outb(const uint8_t *p, size_t n) {
    if (n < 1) return -1;
    uint8_t cmd = p[0];
    // Trigger the SMI. iopl(3) was raised at startup, so this is OK
    // even though port 0xB2 is privileged.
    outb(cmd, APMC_PORT);
    return 0;
}

static int handle_read_phys(const uint8_t *p, size_t n) {
    if (n < 12) return -1;
    uint64_t addr = *(const uint64_t *)(p + 0);
    uint32_t len  = *(const uint32_t *)(p + 8);
    if (len > 0x10000) len = 0x10000;
    off_t pa = (off_t)(addr & ~(off_t)0xFFF);
    size_t map_len = ((addr - pa) + len + 0xFFF) & ~(size_t)0xFFF;
    void *m = mmap(NULL, map_len, PROT_READ, MAP_SHARED, g_devmem, pa);
    if (m == MAP_FAILED) return 0;
    // Just touch every page to make sure the mapping is honored —
    // the result is discarded.
    volatile uint8_t sink = 0;
    for (uint32_t i = 0; i < len; i++) sink ^= ((uint8_t *)m)[(addr - pa) + i];
    (void)sink;
    munmap(m, map_len);
    return 0;
}

static uint32_t dispatch_program(const uint8_t *prog, uint32_t bytes,
                                 uint32_t ncalls) {
    uint32_t off = 0;
    for (uint32_t i = 0; i < ncalls; i++) {
        if (off + 8 > bytes) return 1;
        uint32_t kind = *(const uint32_t *)(prog + off + 0);
        uint32_t size = *(const uint32_t *)(prog + off + 4);
        if (size < 8 || off + size > bytes) return 2;
        const uint8_t *payload = prog + off + 8;
        size_t plen = (size_t)(size - 8);
        int rc = 0;
        switch (kind) {
        case KIND_WRITE_PHYS: rc = handle_write_phys(payload, plen); break;
        case KIND_OUTB:       rc = handle_outb(payload, plen);       break;
        case KIND_READ_PHYS:  rc = handle_read_phys(payload, plen);  break;
        default:              rc = 0; break; // unknown kinds are ignored
        }
        if (rc != 0) return 3;
        off += size;
    }
    return 0;
}

int main(void) {
    if (iopl(3) < 0) {
        fprintf(stderr, "[smi-runner] iopl(3): %s (must run as root)\n",
                strerror(errno));
        return 1;
    }
    if (map_ivshmem() != 0) return 1;
    g_devmem = open("/dev/mem", O_RDWR | O_SYNC);
    if (g_devmem < 0) {
        fprintf(stderr, "[smi-runner] open /dev/mem: %s\n", strerror(errno));
        return 1;
    }
    fprintf(stderr, "[smi-runner] ready, shared=%p size=%zu\n",
            (void *)g_shared, g_shared_size);

    uint32_t last_seq = 0;
    for (;;) {
        uint32_t cur = *u32(g_shared, SMI_OFF_HOST_SEQ);
        if (cur == last_seq) {
            // Cheap idle: yield once. The host typically pokes every
            // few hundred microseconds at full tilt.
            usleep(50);
            continue;
        }
        uint32_t magic  = *u32(g_shared, SMI_OFF_MAGIC);
        uint32_t ncalls = *u32(g_shared, SMI_OFF_NCALLS);
        uint32_t status = 0;
        if (magic != SMI_MAGIC) {
            status = 0xDEAD0001;
        } else if (ncalls == 0 || ncalls > 32) {
            status = 0xDEAD0002;
        } else {
            // Snapshot the program into a local buffer so a host
            // racing with us can't tear it.
            uint8_t buf[SMI_MAX_CALL_BYTES];
            memcpy(buf, (const void *)(g_shared + SMI_OFF_CALLS), sizeof(buf));
            status = dispatch_program(buf, sizeof(buf), ncalls);
        }
        *u32(g_shared, SMI_OFF_GUEST_STAT) = status;
        __sync_synchronize();
        *u32(g_shared, SMI_OFF_GUEST_SEQ) = cur;
        last_seq = cur;
    }
    return 0;
}
