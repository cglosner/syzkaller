// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Pseudo-syscalls for the edk2 (UEFI/OVMF) target.
//
// The single pseudo-syscall syz_edk2_run_program forwards a fuzzer-generated
// program to SyzAgentDxe inside OVMF over a shared memory page (mapped via
// the ivshmem-plain device that QEMU exposes), then waits for SyzAgentDxe to
// complete and returns. The wire format is intentionally minimal so it can
// also be produced by syz-prog2c reproducers.
//
// Wire layout (in the shared memory page, host endianness, little-endian):
//
//   offset 0x0000  uint32 magic    'SYZE' (0x53595A45)
//   offset 0x0004  uint32 ncalls
//   offset 0x0008  uint8  calls[]   syz_edk2_call records, packed
//
// Two control words live just before the program region:
//
//   offset 0x1000  uint32 host_seq  monotonically incremented by the host
//   offset 0x1004  uint32 guest_seq the agent writes this when done
//   offset 0x1008  uint32 guest_status (0 = OK, non-zero = agent error)
//
// The agent spins on (host_seq != guest_seq); the host spins on the inverse.
// Coverage records (PCs) are written by SyzCoverLib into the next region
// starting at offset 0x2000 as (uint32 nr_pcs; uint64 pcs[nr_pcs]).
//
// The shared memory page path is taken from the EDK2_IVSHMEM environment
// variable. If unset, the pseudo-syscall returns ENODEV so syz-executor's
// machine check correctly reports the feature as unavailable instead of
// hanging.

// Standalone syz-prog2c reproducers are compiled as plain C and don't pull in
// the libc headers that the syz-executor build path provides via the surrounding
// includes. Pull them in unconditionally so the generated reproducer compiles
// without further plumbing. Mirrors common_test.h's strategy.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if SYZ_EXECUTOR || __NR_syz_mmap
#include <sys/mman.h>

// syz_mmap(addr vma, len len[addr])
static long syz_mmap(volatile long a0, volatile long a1)
{
	return (long)mmap((void*)a0, a1, PROT_READ | PROT_WRITE,
			  MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0);
}
#endif

#define EDK2_PROGRAM_MAGIC 0x53595A45u

#define EDK2_OFF_MAGIC 0x0000
#define EDK2_OFF_NCALLS 0x0004
#define EDK2_OFF_CALLS 0x0008
#define EDK2_OFF_HOST_SEQ 0x1000
#define EDK2_OFF_GUEST_SEQ 0x1004
#define EDK2_OFF_GUEST_STATUS 0x1008
#define EDK2_OFF_COVER 0x2000
// Comparison ring written by SyzCoverLib's __sanitizer_cov_trace_cmp*
// handlers when the firmware is built with -fsanitize-coverage=trace-cmp.
// Layout: uint32 count, then count entries of 4*uint64 = (type, pc, arg1, arg2).
#define EDK2_OFF_COMPS 0x80000
#define EDK2_COMPS_MAX 512
#define EDK2_CMP_SIZE_MASK 0x7
#define EDK2_CMP_CONST     0x8

#define EDK2_PROG_BYTES (EDK2_OFF_HOST_SEQ - EDK2_OFF_CALLS)
#define EDK2_TIMEOUT_MS 5000

#if SYZ_EXECUTOR || __NR_syz_edk2_run_program

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

struct syz_edk2_channel {
	uint8* base;
	size_t size;
	int fd;
	uint32 host_seq;
};

static struct syz_edk2_channel syz_edk2_chan;

// -----------------------------------------------------------------
// TcgSnapshot / fwsnap fast path.
//
// When vm/qemu.go launches qemu with the libfwsnap.so plugin attached,
// it publishes two extra env vars:
//
//   EDK2_FWSNAP_SHMID      SysV shmem id of the fwsnap control region
//   EDK2_FWSNAP_INPUT_ADDR guest physical address of the firmware-side
//                         gSyzFwfuzzInputBuffer (from the SYZFWFUZZ
//                         debug marker at discovery time)
//   EDK2_FWSNAP_FUZZ_MAX   size of the fuzz_input buffer in bytes
//
// In this mode, each syz_edk2_run_program:
//   1. writes the program into the fwsnap control shmem's fuzz_input
//      area and publishes fuzz_input_addr / fuzz_input_len
//   2. zeros the ivshmem cover count
//   3. writes command=FWSNAP_CMD_RESTORE and waits for it to be acked
//      (the plugin zeros the command byte after picking it up)
//   4. waits for status == FWSNAP_STATUS_DONE
//
// Coverage collection is unchanged: SyzCoverLib writes PCs to the
// cover ring in the ivshmem BAR, which is NOT rolled back by the
// snapshot (the snapshot region covers 0x3c000000:0x04000000 of DRAM
// plus, if ASan is active, the shadow BAR — never the SyzCoverLib
// ring itself). cover_collect reads the ring as before.
//
// The doorbell path (EDK2_FWSNAP_SHMID unset) still works as a
// fallback, so non-snapshot edk2 VMs continue to function unchanged.
// -----------------------------------------------------------------

#define FWSNAP_OFF_COMMAND        0
#define FWSNAP_OFF_STATUS         1
#define FWSNAP_OFF_FUZZ_INPUT_ADR 8
#define FWSNAP_OFF_FUZZ_INPUT_LEN 16
#define FWSNAP_OFF_SHADOW_BASE    40
#define FWSNAP_OFF_SHADOW_SIZE    48
#define FWSNAP_OFF_FUZZ_DATA      64

#define FWSNAP_CMD_NOP     0
#define FWSNAP_CMD_RESTORE 1
// FWSNAP_CMD_RERUN: re-enter the trigger without restoring saved
// memory regions. Only CPU registers (RIP, RSP, etc.) are rolled back
// to their trigger-entry snapshot values, so SyzFwfuzzTrigger re-runs
// cleanly against an UNCHANGED firmware heap/global state. Used for
// subsequent protocol calls within the same fuzzer program, so state
// (allocation table slots, event handles, file handles, ...) persists
// across variant syscalls and resource chains actually work.
// The first call of each program still uses FWSNAP_CMD_RESTORE.
#define FWSNAP_CMD_RERUN   4

#define FWSNAP_STATUS_RESTORED 3
#define FWSNAP_STATUS_DONE     4

struct syz_edk2_fwsnap {
	uint8* base;
	size_t size;
	uint64 fuzz_input_addr;
	size_t fuzz_max;
	int attached;
	// program_started tracks whether we've sent RESTORE for the
	// current fuzzer program yet. Reset by syz_edk2_fwsnap_program_reset
	// at the top of execute_one (see executor.cc). Without this, every
	// protocol call would roll firmware state back to the snapshot and
	// cross-call state chaining would be impossible.
	int program_started;
	// Per-program slot counters that mirror SyzAgentDxe's deterministic
	// slot allocator. The agent picks the lowest empty slot for each
	// producer call; with CMD_RERUN preserving state across calls,
	// the Nth producer call of a given kind hits slot N-1. We use these
	// counters as the return value of syz_edk2_run_program to populate
	// syzkaller resources (edk2_alloc_slot, edk2_event_slot, ...) with
	// values that match actual firmware slots, so consumer variants
	// ($free_pool, $close_event, ...) get a live slot as input.
	//
	// This is only approximate — a $free_pool in the middle of a
	// program would empty a slot that the next $allocate_pool would
	// re-fill, creating a discrepancy between our counter and the
	// firmware's real slot. The mutator still benefits from a linked
	// producer/consumer contract even when the value is imperfect.
	int alloc_counter;
	int event_counter;
	int file_counter;
	int image_counter;
};

static struct syz_edk2_fwsnap syz_edk2_fws;

static void syz_edk2_fwsnap_program_reset(void)
{
	syz_edk2_fws.program_started = 0;
	syz_edk2_fws.alloc_counter = 0;
	syz_edk2_fws.event_counter = 0;
	syz_edk2_fws.file_counter = 0;
	syz_edk2_fws.image_counter = 0;
}

static int syz_edk2_attach_fwsnap(struct syz_edk2_fwsnap* fws)
{
	if (fws->attached)
		return 0;
	const char* shmid_s = getenv("EDK2_FWSNAP_SHMID");
	const char* addr_s = getenv("EDK2_FWSNAP_INPUT_ADDR");
	const char* fmax_s = getenv("EDK2_FWSNAP_FUZZ_MAX");
	if (!shmid_s || !*shmid_s || !addr_s || !*addr_s || !fmax_s || !*fmax_s) {
		fws->attached = -1; // decided: NOT snapshot mode
		return -1;
	}
	int shmid = atoi(shmid_s);
	void* p = shmat(shmid, NULL, 0);
	if (p == (void*)-1) {
		debug("syz_edk2_fwsnap: shmat(%d) failed: %s\n",
		      shmid, strerror(errno));
		fws->attached = -1;
		return -1;
	}
	fws->base = (uint8*)p;
	fws->fuzz_max = (size_t)strtoul(fmax_s, NULL, 0);
	fws->size = 64 + fws->fuzz_max; // header + data area
	fws->fuzz_input_addr = strtoull(addr_s, NULL, 0);
	fws->attached = 1;
	debug("syz_edk2_fwsnap: attached shmid=%d input_addr=0x%lx fuzz_max=%zu\n",
	      shmid, (unsigned long)fws->fuzz_input_addr, fws->fuzz_max);
	return 0;
}

// Returns 1 if fwsnap mode is active, 0 if doorbell mode, -1 on error.
static int syz_edk2_fwsnap_mode(void)
{
	if (syz_edk2_fws.attached == 0) {
		syz_edk2_attach_fwsnap(&syz_edk2_fws);
	}
	return syz_edk2_fws.attached > 0 ? 1 : 0;
}

// Submit a program via the fwsnap RESTORE path. prog points at the
// wire-format program (magic + ncalls + call records). bytes is the
// length of the program excluding the 8-byte header-slot that
// syz_edk2_run_program wants to prepend — we re-add it from the
// prog data itself.
static int syz_edk2_fwsnap_run(const uint8* prog, size_t bytes)
{
	struct syz_edk2_fwsnap* fws = &syz_edk2_fws;
	if (!fws->attached || fws->base == NULL) {
		errno = ENODEV;
		return -1;
	}
	if (bytes > fws->fuzz_max) {
		errno = EMSGSIZE;
		return -1;
	}
	// Copy program into the fuzz_input_data area (after the 64-byte
	// control header).
	memcpy(fws->base + FWSNAP_OFF_FUZZ_DATA, prog, bytes);
	// Tell the plugin where to inject the input in the guest (the
	// SyzFwfuzzInputBuffer physical address from discovery) and
	// how many bytes to copy.
	*(volatile uint64*)(fws->base + FWSNAP_OFF_FUZZ_INPUT_ADR) =
	    fws->fuzz_input_addr;
	*(volatile uint64*)(fws->base + FWSNAP_OFF_FUZZ_INPUT_LEN) =
	    (uint64)bytes;
	// Zero the cover ring before we trigger so we only read this
	// iteration's PCs. Mirror cover_reset().
	if (syz_edk2_chan.base != NULL) {
		*(volatile uint32*)(syz_edk2_chan.base + EDK2_OFF_COVER) = 0;
	}
	// Pick the right command for this iteration:
	//   - FWSNAP_CMD_RESTORE on the first protocol call of a fuzzer
	//     program: roll back all saved memory regions (pristine
	//     firmware state).
	//   - FWSNAP_CMD_RERUN on subsequent protocol calls of the same
	//     program: preserve firmware memory (heap, globals, agent
	//     allocation table, event table, ...) so cross-call state
	//     chains work. Only CPU registers roll back, re-entering
	//     SyzFwfuzzTrigger cleanly.
	// program_started is cleared in syz_edk2_fwsnap_program_reset,
	// which executor.cc calls at the top of execute_one per program.
	//
	// Two-phase protocol (unchanged from RESTORE-only): status is
	// already DONE from the previous iteration, so we must wait for
	// it to transition OUT of DONE (do_restore / do_rerun sets it to
	// RESTORED) before waiting for it to come BACK to DONE. Otherwise
	// the stale DONE short-circuits and the iteration never actually
	// ran — empty cover ring, stale ASan shadow, etc.
	uint8 run_cmd = fws->program_started ? FWSNAP_CMD_RERUN : FWSNAP_CMD_RESTORE;
	fws->program_started = 1;
	__atomic_store_n((volatile uint8*)(fws->base + FWSNAP_OFF_COMMAND),
			 run_cmd, __ATOMIC_RELEASE);
	struct timespec start, now;
	clock_gettime(CLOCK_MONOTONIC, &start);
	// Phase A: wait for the plugin to pick up the RESTORE command
	// AND execute do_restore (which sets status=RESTORED). This is
	// where we detect that the new iteration has actually started.
	for (;;) {
		uint8 st = __atomic_load_n(
		    (volatile uint8*)(fws->base + FWSNAP_OFF_STATUS),
		    __ATOMIC_ACQUIRE);
		uint8 cmd = __atomic_load_n(
		    (volatile uint8*)(fws->base + FWSNAP_OFF_COMMAND),
		    __ATOMIC_ACQUIRE);
		// Success: status has transitioned out of DONE into
		// RESTORED (or later), AND the plugin has acked the
		// command (written NOP back).
		if (cmd == FWSNAP_CMD_NOP && st != FWSNAP_STATUS_DONE)
			break;
		clock_gettime(CLOCK_MONOTONIC, &now);
		long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000 +
				  (now.tv_nsec - start.tv_nsec) / 1000000;
		if (elapsed_ms >= EDK2_TIMEOUT_MS) {
			errno = ETIMEDOUT;
			return -1;
		}
		struct timespec ts = {0, 100 * 1000};
		nanosleep(&ts, NULL);
	}
	// Phase B: wait for status=DONE. The iteration ran the guest
	// body and hit the exit_trigger PC.
	for (;;) {
		uint8 st = __atomic_load_n(
		    (volatile uint8*)(fws->base + FWSNAP_OFF_STATUS),
		    __ATOMIC_ACQUIRE);
		if (st == FWSNAP_STATUS_DONE)
			break;
		clock_gettime(CLOCK_MONOTONIC, &now);
		long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000 +
				  (now.tv_nsec - start.tv_nsec) / 1000000;
		if (elapsed_ms >= EDK2_TIMEOUT_MS) {
			errno = ETIMEDOUT;
			return -1;
		}
		struct timespec ts = {0, 100 * 1000};
		nanosleep(&ts, NULL);
	}
	return 0;
}

static int syz_edk2_open_channel(struct syz_edk2_channel* ch)
{
	if (ch->base != NULL)
		return 0;
	const char* path = getenv("EDK2_IVSHMEM");
	debug("syz_edk2_open_channel: EDK2_IVSHMEM=%s\n", path ? path : "(null)");
	if (path == NULL || *path == '\0') {
		errno = ENODEV;
		return -1;
	}
	int fd = open(path, O_RDWR);
	if (fd < 0)
		return -1;
	struct stat st;
	if (fstat(fd, &st) < 0) {
		close(fd);
		return -1;
	}
	if (st.st_size < EDK2_OFF_COVER + 4096) {
		close(fd);
		errno = EINVAL;
		return -1;
	}
	void* p = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		close(fd);
		return -1;
	}
	ch->base = (uint8*)p;
	ch->size = (size_t)st.st_size;
	ch->fd = fd;
	ch->host_seq = *(volatile uint32*)(ch->base + EDK2_OFF_HOST_SEQ);
	return 0;
}

static long syz_edk2_run_program(volatile long a0)
{
	if (syz_edk2_open_channel(&syz_edk2_chan) < 0)
		return -1;
	struct syz_edk2_channel* ch = &syz_edk2_chan;
	const uint8* prog = (const uint8*)a0;
	if (prog == NULL) {
		errno = EFAULT;
		return -1;
	}
	uint32 magic = *(const uint32*)(prog + EDK2_OFF_MAGIC);
	if (magic != EDK2_PROGRAM_MAGIC) {
		errno = EINVAL;
		return -1;
	}
	uint32 ncalls = *(const uint32*)(prog + EDK2_OFF_NCALLS);
	if (ncalls == 0 || ncalls > 32) {
		errno = EINVAL;
		return -1;
	}
	// TcgSnapshot fast path: if the executor env carries a valid
	// EDK2_FWSNAP_SHMID, submit via the plugin's RESTORE protocol
	// instead of the doorbell. Coverage still comes from the
	// ivshmem cover ring (SyzCoverLib writes PCs into the BAR,
	// which is OUTSIDE the snapshot region so it survives the
	// memory rollback and the host can drain it each iteration).
	if (syz_edk2_fwsnap_mode() == 1) {
		long res = syz_edk2_fwsnap_run(prog, EDK2_PROG_BYTES);
		if (res < 0) {
			return res;
		}
		// Return a slot value consistent with SyzAgentDxe's
		// deterministic allocator so syzkaller resource chains
		// (allocate→free, create_event→close_event, ...) can line
		// up producer and consumer calls without firmware write-back.
		// We look at the FIRST call's id in the program (variants
		// always send 1-call programs), pick the matching counter,
		// and return its pre-increment value.
		if (ncalls >= 1) {
			const uint8* call_hdr = prog + EDK2_OFF_CALLS;
			uint32 call_id = *(const uint32*)call_hdr;
			struct syz_edk2_fwsnap* fws = &syz_edk2_fws;
			switch (call_id) {
			case 200: // AllocatePool
			case 202: // AllocatePages
				return fws->alloc_counter++;
			case 250: // CreateEvent
				return fws->event_counter++;
			case 700: // SimpleFsOpenVolume
			case 701: // FileOpen
				return fws->file_counter++;
			case 790: // LoadImage
				return fws->image_counter++;
			default:
				return 0;
			}
		}
		return 0;
	}
	// Copy header + raw call records into the shared region. We trust
	// the prog package to have produced something the agent can parse;
	// the agent does its own bounds checking before dereferencing.
	memcpy(ch->base + EDK2_OFF_MAGIC, prog, EDK2_PROG_BYTES);
	// Reset coverage ring (first uint32 is the PC count).
	*(volatile uint32*)(ch->base + EDK2_OFF_COVER) = 0;
	// Doorbell.
	ch->host_seq++;
	__atomic_store_n((volatile uint32*)(ch->base + EDK2_OFF_GUEST_STATUS), 0,
			 __ATOMIC_RELEASE);
	__atomic_store_n((volatile uint32*)(ch->base + EDK2_OFF_HOST_SEQ),
			 ch->host_seq, __ATOMIC_RELEASE);
	// Wait for the guest to ack.
	struct timespec start, now;
	clock_gettime(CLOCK_MONOTONIC, &start);
	for (;;) {
		uint32 guest_seq = __atomic_load_n(
		    (volatile uint32*)(ch->base + EDK2_OFF_GUEST_SEQ),
		    __ATOMIC_ACQUIRE);
		if (guest_seq == ch->host_seq)
			break;
		clock_gettime(CLOCK_MONOTONIC, &now);
		long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000 +
				  (now.tv_nsec - start.tv_nsec) / 1000000;
		if (elapsed_ms >= EDK2_TIMEOUT_MS) {
			errno = ETIMEDOUT;
			return -1;
		}
		// Yield to let the kernel reschedule QEMU.
		struct timespec ts = {0, 100 * 1000};
		nanosleep(&ts, NULL);
	}
	uint32 status = __atomic_load_n(
	    (volatile uint32*)(ch->base + EDK2_OFF_GUEST_STATUS),
	    __ATOMIC_ACQUIRE);
	if (status != 0) {
		errno = EIO;
		return -1;
	}
	return 0;
}

#endif // SYZ_EXECUTOR || __NR_syz_edk2_run_program

// Threading primitives. The edk2 executor runs on Linux (HostFuzzer mode),
// so we can use plain pthread + atomics. The interface mirrors the one in
// common_linux.h / common_fuchsia.h so executor.cc's SYZ_THREADED block
// builds unchanged.
#if SYZ_EXECUTOR || SYZ_THREADED
#include <errno.h>
#include <pthread.h>
#include <time.h>

typedef struct {
	pthread_mutex_t mu;
	pthread_cond_t cv;
	int state;
} event_t;

static void event_init(event_t* ev)
{
	pthread_mutex_init(&ev->mu, NULL);
	pthread_cond_init(&ev->cv, NULL);
	ev->state = 0;
}

static void event_reset(event_t* ev)
{
	pthread_mutex_lock(&ev->mu);
	ev->state = 0;
	pthread_mutex_unlock(&ev->mu);
}

static void event_set(event_t* ev)
{
	pthread_mutex_lock(&ev->mu);
	if (ev->state)
		exitf("event already set");
	ev->state = 1;
	pthread_cond_broadcast(&ev->cv);
	pthread_mutex_unlock(&ev->mu);
}

static void event_wait(event_t* ev)
{
	pthread_mutex_lock(&ev->mu);
	while (!ev->state)
		pthread_cond_wait(&ev->cv, &ev->mu);
	pthread_mutex_unlock(&ev->mu);
}

static int event_isset(event_t* ev)
{
	pthread_mutex_lock(&ev->mu);
	int res = ev->state;
	pthread_mutex_unlock(&ev->mu);
	return res;
}

static int event_timedwait(event_t* ev, uint64 timeout_ms)
{
	uint64 deadline_ms = current_time_ms() + timeout_ms;
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec += timeout_ms / 1000;
	ts.tv_nsec += (timeout_ms % 1000) * 1000 * 1000;
	if (ts.tv_nsec >= 1000 * 1000 * 1000) {
		ts.tv_nsec -= 1000 * 1000 * 1000;
		ts.tv_sec += 1;
	}
	pthread_mutex_lock(&ev->mu);
	int res = 0;
	while (!ev->state) {
		if (pthread_cond_timedwait(&ev->cv, &ev->mu, &ts) == ETIMEDOUT)
			break;
		if (current_time_ms() > deadline_ms)
			break;
	}
	res = ev->state;
	pthread_mutex_unlock(&ev->mu);
	return res;
}
#endif

// Sandboxing is a no-op for the edk2 host executor: the dangerous code
// runs inside the QEMU guest, not in this process.
#if SYZ_EXECUTOR || SYZ_SANDBOX_NONE
static void loop();
static int do_sandbox_none(void)
{
	loop();
	return 0;
}
#endif

// remove_dir is referenced by executor_runner.h's ExecuteBinary path inside
// syz-executor proper; standalone syz-prog2c reproducers never call it, so
// gate it on SYZ_EXECUTOR to keep the reproducer C file lean and quiet.
#if SYZ_EXECUTOR
#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void remove_dir(const char* dir)
{
	DIR* dp = opendir(dir);
	if (dp == NULL)
		return;
	struct dirent* ep;
	while ((ep = readdir(dp))) {
		if (strcmp(ep->d_name, ".") == 0 || strcmp(ep->d_name, "..") == 0)
			continue;
		char path[PATH_MAX];
		snprintf(path, sizeof(path), "%s/%s", dir, ep->d_name);
		struct stat st;
		if (lstat(path, &st) == 0 && S_ISDIR(st.st_mode))
			remove_dir(path);
		else
			unlink(path);
	}
	closedir(dp);
	rmdir(dir);
}
#endif
