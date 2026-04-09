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

#define EDK2_PROG_BYTES (EDK2_OFF_HOST_SEQ - EDK2_OFF_CALLS)
#define EDK2_TIMEOUT_MS 5000

#if SYZ_EXECUTOR || __NR_syz_edk2_run_program

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
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

static int syz_edk2_open_channel(struct syz_edk2_channel* ch)
{
	if (ch->base != NULL)
		return 0;
	const char* path = getenv("EDK2_IVSHMEM");
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
