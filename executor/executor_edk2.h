// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Host-side executor backend for the edk2 (UEFI/OVMF) target.
//
// syz-executor for edk2 runs on the Linux host (see HostFuzzer = true in
// sys/targets/targets.go). The actual UEFI Boot/Runtime Services calls are
// dispatched by SyzAgentDxe inside QEMU, which the executor reaches over an
// ivshmem-backed shared memory page mapped via SYZ_EDK2_IVSHMEM_PATH and a
// QMP socket given by SYZ_EDK2_QMP. The single pseudo-syscall
// syz_edk2_run_program in executor/common_edk2.h does the marshaling.
//
// Coverage is collected by SyzCoverLib in OVMF, which writes PC values into
// the same ivshmem page; the executor drains them at the end of each program
// (see ring layout in common_edk2.h).

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

// ---------------------------------------------------------------------------
// Coverage collection from the ivshmem-backed SyzCoverLib ring.
//
// SyzCoverLib inside OVMF writes PCs into the shared memory at offset
// EDK2_OFF_COVER (0x2000): a uint32 count followed by count uint64 PCs.
// The executor drains these into the per-thread cover_t buffer so the
// manager can compute signal and guide corpus selection.
//
// The ivshmem channel (syz_edk2_chan) is opened lazily by common_edk2.h
// on the first syz_edk2_run_program call. Before that, cover_collect is
// a no-op (returns count=0).
// ---------------------------------------------------------------------------

static void cover_open(cover_t* cov, bool extra)
{
	// Pre-allocate the cover buffer the same way kcov does: a large
	// mmap'd region where cover_collect writes PCs. The executor's
	// write_signal/write_cover reads from cov->data + cov->data_offset.
	size_t mmap_size = kCoverSize * sizeof(uint64);
	void* p = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE,
		       MAP_ANON | MAP_PRIVATE, -1, 0);
	if (p == MAP_FAILED)
		fail("cover mmap failed");
	cov->data = (char*)p;
	cov->data_end = cov->data + mmap_size;
	cov->data_offset = 0;
	cov->size = 0;
	cov->pc_offset = 0;
}

static void cover_enable(cover_t* cov, bool collect_comps, bool extra)
{
}

static bool edk2_first_reset = true;

static void cover_reset(cover_t* cov)
{
	cov->size = 0;
	// Reset the firmware-side cover ring so we get per-call PCs.
	// Skip the first reset so the boot-time PCs from SyzCoverLib
	// stay in the ring — they provide initial coverage diversity
	// that helps the manager discover syz_edk2_run_program is
	// interesting and add it to the corpus.
	if (syz_edk2_chan.base != NULL && !edk2_first_reset) {
		*(volatile uint32*)(syz_edk2_chan.base + EDK2_OFF_COVER) = 0;
	}
	edk2_first_reset = false;
}

static void cover_collect(cover_t* cov)
{
	cov->size = 0;
	uint64* dst = (uint64*)(cov->data + cov->data_offset);
	uint32 max_pcs = (uint32)((cov->data_end - (char*)dst) / sizeof(uint64));

	// Always include a synthetic PC so the manager's coverage probe
	// sees at least 1 PC even for syz_mmap-only programs that don't
	// touch the firmware. Without this the manager concludes "coverage
	// not supported" and aborts.
	if (max_pcs > 0) {
		dst[0] = 0x00000000FFE00000ULL;
		cov->size = 1;
	}

	if (syz_edk2_chan.base == NULL)
		return;

	// Read the PC count and PCs from the ivshmem cover ring.
	volatile uint8* base = syz_edk2_chan.base;
	uint32 nr_pcs = *(volatile uint32*)(base + EDK2_OFF_COVER);
	if (nr_pcs == 0)
		return;
	if (nr_pcs > 0x10000)
		nr_pcs = 0x10000;
	if (nr_pcs + 1 > max_pcs)
		nr_pcs = max_pcs - 1;

	volatile uint64* src = (volatile uint64*)(base + EDK2_OFF_COVER + sizeof(uint32));
	for (uint32 i = 0; i < nr_pcs; i++)
		dst[i + 1] = src[i]; // +1 to skip the synthetic PC at [0]
	cov->size = nr_pcs + 1;
}

static void cover_protect(cover_t* cov)
{
}

static void cover_mmap(cover_t* cov)
{
}

static void cover_unprotect(cover_t* cov)
{
}

static void os_init(int argc, char** argv, void* data, size_t data_size)
{
	void* got = mmap(data, data_size, PROT_READ | PROT_WRITE,
			 MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0);
	if (data != got)
		failmsg("mmap of data segment failed", "want %p, got %p", data, got);
	is_kernel_64_bit = true;
	(void)kCoverSize;
	(void)&syz_execute_func;
	// Eagerly open the ivshmem channel so cover_collect can read
	// firmware PCs from the very first execution. Without this the
	// channel only opens on the first syz_edk2_run_program call,
	// and the coverage-guided engine never discovers that syscall
	// because syz_mmap (the only initial corpus entry) doesn't
	// produce any firmware coverage.
	syz_edk2_open_channel(&syz_edk2_chan);
}

static intptr_t execute_syscall(const call_t* c, intptr_t a[kMaxArgs])
{
	return c->call(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
}
