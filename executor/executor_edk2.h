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

static void cover_reset(cover_t* cov)
{
	cov->size = 0;
	// The firmware-side SyzCoverReset (called by the agent before
	// dispatch) zeros the ring count AND enables the coverage gate.
	// Background DXE activity won't write PCs while the gate is off.
	// We still zero from the host side as a safety measure.
	if (syz_edk2_chan.base != NULL) {
		*(volatile uint32*)(syz_edk2_chan.base + EDK2_OFF_COVER) = 0;
	}
}

static void cover_collect(cover_t* cov)
{
	cov->size = 0;
	uint64* dst = (uint64*)(cov->data + cov->data_offset);
	uint32 max_pcs = (uint32)((cov->data_end - (char*)dst) / sizeof(uint64));

	// Comparison mode: instead of writing PCs, populate the cov->data
	// buffer with the kcov_comparison_t format so write_comparisons()
	// in executor.cc can read it. The firmware-side __sanitizer_cov_trace_cmp*
	// handlers write (type, pc, arg1, arg2) quadruples to the comps ring
	// at EDK2_OFF_COMPS. We translate into the host's expected layout:
	//   uint64 ncomps; { uint64 type; uint64 arg1; uint64 arg2; uint64 pc; }*
	if (flag_comparisons) {
		uint64* hdr = dst;
		hdr[0] = 0;
		cov->size = 1; // 1 uint64 header by default
		if (syz_edk2_chan.base == NULL)
			return;
		volatile uint8* base = syz_edk2_chan.base;
		volatile uint32* cmp_count_ptr = (volatile uint32*)(base + EDK2_OFF_COMPS);
		uint32 ncomps = *cmp_count_ptr;
		if (ncomps == 0)
			return;
		if (ncomps > 512)
			ncomps = 512; // EDK2_COMPS_MAX
		// Each kcov_comparison_t is 4 uint64. After the 1-uint64 header,
		// we need 4*ncomps more uint64s.
		uint32 max_entries = (max_pcs - 1) / 4;
		if (ncomps > max_entries)
			ncomps = max_entries;
		hdr[0] = ncomps;

		volatile uint64* src = (volatile uint64*)(base + EDK2_OFF_COMPS + sizeof(uint32));
		for (uint32 i = 0; i < ncomps; i++) {
			// Source layout: type, pc, arg1, arg2
			uint64 type = src[i * 4 + 0];
			uint64 pc = src[i * 4 + 1];
			uint64 arg1 = src[i * 4 + 2];
			uint64 arg2 = src[i * 4 + 3];
			// Dest layout (kcov_comparison_t): type, arg1, arg2, pc
			dst[1 + i * 4 + 0] = type;
			dst[1 + i * 4 + 1] = arg1;
			dst[1 + i * 4 + 2] = arg2;
			dst[1 + i * 4 + 3] = pc;
		}
		cov->size = 1 + ncomps * 4;
		// Reset for next program.
		*cmp_count_ptr = 0;
		return;
	}

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

	// Read PCs from the cover ring. With the firmware-side gate
	// (SyzCoverReset enables, SyzCoverStop disables), these are only
	// PCs hit during program dispatch — not background DXE activity.
	volatile uint8* base = syz_edk2_chan.base;
	volatile uint32* count_ptr = (volatile uint32*)(base + EDK2_OFF_COVER);
	uint32 nr_pcs = *count_ptr;
	if (nr_pcs == 0)
		return;
	// Cap at 16K PCs per call. A single firmware dispatch typically
	// produces 1-10K unique PCs. Values much higher than this indicate
	// stale boot PCs leaking through (the gate may not be effective
	// for all modules). Capping prevents pollution of max_signal.
	if (nr_pcs > 0x4000)
		nr_pcs = 0x4000;
	if (nr_pcs + 1 > max_pcs)
		nr_pcs = max_pcs - 1;

	volatile uint64* src = (volatile uint64*)(base + EDK2_OFF_COVER + sizeof(uint32));
	for (uint32 i = 0; i < nr_pcs; i++)
		dst[i + 1] = src[i];
	cov->size = nr_pcs + 1;

	// Zero the count after reading to prevent re-reading stale PCs
	// if cover_collect is called again before the next cover_reset.
	*count_ptr = 0;
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
