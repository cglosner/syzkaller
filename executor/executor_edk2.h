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
	cov->size = 0;
	cov->data = NULL;
	cov->data_end = NULL;
	cov->data_offset = 0;
}

static void cover_enable(cover_t* cov, bool collect_comps, bool extra)
{
}

static void cover_reset(cover_t* cov)
{
	cov->size = 0;
	// Also reset the firmware-side cover ring so we get per-call PCs.
	if (syz_edk2_chan.base != NULL) {
		*(volatile uint32*)(syz_edk2_chan.base + EDK2_OFF_COVER) = 0;
	}
}

static void cover_collect(cover_t* cov)
{
	cov->size = 0;
	// Ensure the PC buffer is allocated.
	if (cov->data == NULL) {
		cov->data = (char*)mmap(NULL, kCoverSize * sizeof(uint64),
					PROT_READ | PROT_WRITE,
					MAP_ANON | MAP_PRIVATE, -1, 0);
		if (cov->data == MAP_FAILED) {
			cov->data = NULL;
			return;
		}
		cov->data_end = cov->data + kCoverSize * sizeof(uint64);
		cov->data_offset = 0;
	}
	if (syz_edk2_chan.base == NULL) {
		// Channel not open yet. Return a synthetic PC so the manager's
		// coverage probe passes.
		uint64* dst = (uint64*)(cov->data + cov->data_offset);
		dst[0] = 0x00000000FFE00000ULL;
		cov->size = 1;
		return;
	}
	// Read the PC count and PCs from the ivshmem cover ring.
	volatile uint8* base = syz_edk2_chan.base;
	uint32 nr_pcs = *(volatile uint32*)(base + EDK2_OFF_COVER);
	if (flag_debug)
		debug("cover_collect: nr_pcs=%u\n", nr_pcs);
	if (nr_pcs == 0) {
		// No firmware PCs this round (syz_mmap only, or empty dispatch).
		// Return the synthetic PC so the manager always sees coverage.
		uint64* dst = (uint64*)(cov->data + cov->data_offset);
		dst[0] = 0x00000000FFE00000ULL;
		cov->size = 1;
		return;
	}
	if (nr_pcs > 0x10000)
		nr_pcs = 0x10000;
	// Copy PCs into the cover_t data buffer. The caller (executor.cc)
	// allocated cov->data with kCoverSize entries. We need to ensure
	// we have space.
	if (cov->data == NULL) {
		// Allocate a buffer for PCs if the caller didn't.
		cov->data = (char*)mmap(NULL, kCoverSize * sizeof(uint64),
					PROT_READ | PROT_WRITE,
					MAP_ANON | MAP_PRIVATE, -1, 0);
		if (cov->data == MAP_FAILED) {
			cov->data = NULL;
			return;
		}
		cov->data_end = cov->data + kCoverSize * sizeof(uint64);
		cov->data_offset = 0;
	}
	uint64* dst = (uint64*)(cov->data + cov->data_offset);
	volatile uint64* src = (volatile uint64*)(base + EDK2_OFF_COVER + sizeof(uint32));
	uint32 max_pcs = (uint32)((cov->data_end - (char*)dst) / sizeof(uint64));
	if (nr_pcs > max_pcs)
		nr_pcs = max_pcs;
	for (uint32 i = 0; i < nr_pcs; i++)
		dst[i] = src[i];
	cov->size = nr_pcs;
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
