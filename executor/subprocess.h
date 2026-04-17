// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <vector>

// Subprocess allows to start and wait for a subprocess.
class Subprocess
{
public:
	Subprocess(const char** argv, const std::vector<std::pair<int, int>>& fds)
	{
		posix_spawn_file_actions_t actions;
		if (posix_spawn_file_actions_init(&actions))
			fail("posix_spawn_file_actions_init failed");
		int max_fd = 0;
		for (auto pair : fds)
			max_fd = std::max(max_fd, pair.second);
		for (auto pair : fds) {
			if (pair.first != -1) {
				// Remapping won't work if fd's overlap with the target range:
				// we can dup something onto fd we need to dup later, in such case the later fd
				// will be wrong. Resolving this would require some tricky multi-pass remapping.
				// So we just require the caller to not do that.
				if (pair.first <= max_fd)
					failmsg("bad subprocess fd", "%d->%d max_fd=%d",
						pair.first, pair.second, max_fd);
				if (posix_spawn_file_actions_adddup2(&actions, pair.first, pair.second))
					fail("posix_spawn_file_actions_adddup2 failed");
			} else {
				if (posix_spawn_file_actions_addclose(&actions, pair.second))
					fail("posix_spawn_file_actions_addclose failed");
			}
		}
		for (int i = max_fd + 1; i < kFdLimit; i++) {
			if (posix_spawn_file_actions_addclose(&actions, i))
				fail("posix_spawn_file_actions_addclose failed");
		}

		posix_spawnattr_t attr;
		if (posix_spawnattr_init(&attr))
			fail("posix_spawnattr_init failed");
		// Create new process group so that we can kill all processes in the group.
		if (posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP))
			fail("posix_spawnattr_setflags failed");

		// Build the child environment. We pass a minimal set to avoid
		// interference, but edk2 needs EDK2_IVSHMEM for the ivshmem
		// shared memory transport. When TcgSnapshot mode is enabled,
		// we also forward EDK2_FWSNAP_SHMID / EDK2_FWSNAP_INPUT_ADDR
		// / EDK2_FWSNAP_FUZZ_MAX so syz_edk2_run_program can attach
		// to the fwsnap control region and use the plugin's RESTORE
		// path instead of the ivshmem doorbell.
		const char* edk2_ivshmem = getenv("EDK2_IVSHMEM");
		const char* edk2_fwsnap_shmid = getenv("EDK2_FWSNAP_SHMID");
		const char* edk2_fwsnap_addr = getenv("EDK2_FWSNAP_INPUT_ADDR");
		const char* edk2_fwsnap_fmax = getenv("EDK2_FWSNAP_FUZZ_MAX");
		static char edk2_ivshmem_buf[512];
		static char edk2_fwsnap_shmid_buf[64];
		static char edk2_fwsnap_addr_buf[64];
		static char edk2_fwsnap_fmax_buf[64];
		if (edk2_ivshmem)
			snprintf(edk2_ivshmem_buf, sizeof(edk2_ivshmem_buf),
				 "EDK2_IVSHMEM=%s", edk2_ivshmem);
		if (edk2_fwsnap_shmid)
			snprintf(edk2_fwsnap_shmid_buf, sizeof(edk2_fwsnap_shmid_buf),
				 "EDK2_FWSNAP_SHMID=%s", edk2_fwsnap_shmid);
		if (edk2_fwsnap_addr)
			snprintf(edk2_fwsnap_addr_buf, sizeof(edk2_fwsnap_addr_buf),
				 "EDK2_FWSNAP_INPUT_ADDR=%s", edk2_fwsnap_addr);
		if (edk2_fwsnap_fmax)
			snprintf(edk2_fwsnap_fmax_buf, sizeof(edk2_fwsnap_fmax_buf),
				 "EDK2_FWSNAP_FUZZ_MAX=%s", edk2_fwsnap_fmax);
		// Build the env array dynamically so we can skip unset vars.
		static const char* child_envp_buf[8];
		int envc = 0;
		child_envp_buf[envc++] = "ASAN_OPTIONS=handle_segv=0 allow_user_segv_handler=1 detect_leaks=0";
		child_envp_buf[envc++] = "GLIBC_TUNABLES=glibc.pthread.rseq=0";
		if (edk2_ivshmem)
			child_envp_buf[envc++] = edk2_ivshmem_buf;
		if (edk2_fwsnap_shmid)
			child_envp_buf[envc++] = edk2_fwsnap_shmid_buf;
		if (edk2_fwsnap_addr)
			child_envp_buf[envc++] = edk2_fwsnap_addr_buf;
		if (edk2_fwsnap_fmax)
			child_envp_buf[envc++] = edk2_fwsnap_fmax_buf;
		child_envp_buf[envc] = nullptr;
		const char** child_envp = child_envp_buf;

		if (posix_spawnp(&pid_, argv[0], &actions, &attr,
				 const_cast<char**>(argv), const_cast<char**>(child_envp)))
			fail("posix_spawnp failed");

		if (posix_spawn_file_actions_destroy(&actions))
			fail("posix_spawn_file_actions_destroy failed");
		if (posix_spawnattr_destroy(&attr))
			fail("posix_spawnattr_destroy failed");
	}

	~Subprocess()
	{
		if (pid_)
			KillAndWait();
	}

	int KillAndWait()
	{
		if (!pid_)
			fail("subprocess hasn't started or already waited");
		kill(pid_, SIGKILL);
		int pid = 0;
		int wstatus = 0;
		do
			pid = waitpid(pid_, &wstatus, WAIT_FLAGS);
		while (pid == -1 && errno == EINTR);
		if (pid != pid_)
			failmsg("child wait failed", "pid_=%d pid=%d", pid_, pid);
		if (WIFSTOPPED(wstatus))
			failmsg("child stopped", "status=%d", wstatus);
		pid_ = 0;
		return ExitStatus(wstatus);
	}

	int WaitAndKill(uint64 timeout_ms)
	{
		if (!pid_)
			fail("subprocess hasn't started or already waited");
		uint64 start = current_time_ms();
		int wstatus = 0;
		for (;;) {
			sleep_ms(10);
			if (waitpid(pid_, &wstatus, WNOHANG | WAIT_FLAGS) == pid_)
				break;
			if (current_time_ms() - start > timeout_ms) {
				kill(-pid_, SIGKILL);
				kill(pid_, SIGKILL);
			}
		}
		pid_ = 0;
		return ExitStatus(wstatus);
	}

private:
	int pid_ = 0;

	static int ExitStatus(int wstatus)
	{
		if (WIFEXITED(wstatus))
			return WEXITSTATUS(wstatus);
		if (WIFSIGNALED(wstatus)) {
			// Map signal numbers to some reasonable exit statuses.
			// We only log them and compare to kFailStatus, so ensure it's not kFailStatus
			// and not 0, otherwise return the signal as is (e.g. exit status 11 is SIGSEGV).
			switch (WTERMSIG(wstatus)) {
			case kFailStatus:
				return kFailStatus - 1;
			case 0:
				return kFailStatus - 2;
			default:
				return WTERMSIG(wstatus);
			}
		}
		// This may be possible in WIFSTOPPED case for C programs.
		return kFailStatus - 3;
	}

	Subprocess(const Subprocess&) = delete;
	Subprocess& operator=(const Subprocess&) = delete;
};
