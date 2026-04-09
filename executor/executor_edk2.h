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

#include "nocover.h"

static void os_init(int argc, char** argv, void* data, size_t data_size)
{
	void* got = mmap(data, data_size, PROT_READ | PROT_WRITE,
			 MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0);
	if (data != got)
		failmsg("mmap of data segment failed", "want %p, got %p", data, got);
	is_kernel_64_bit = true;
	// kCoverSize and syz_execute_func are file-scope symbols in
	// executor.cc / common.h whose only references live behind cover-aware
	// or text-aware code paths that we don't enable on edk2. Touching them
	// here keeps -Wunused-{const-variable,function} happy without forking
	// the shared headers.
	(void)kCoverSize;
	(void)&syz_execute_func;
}

static intptr_t execute_syscall(const call_t* c, intptr_t a[kMaxArgs])
{
	return c->call(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
}
