// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// tcgsnap.go — TCG + fwsnap snapshot fuzzing support for the
// standalone syz-edk2-fuzz driver.
//
// When -tcg-snapshot is set, the driver:
//
//   1. Performs a pre-discovery boot in TCG mode (~45s) to capture the
//      runtime PCs of SyzFwfuzzTrigger and the physical address of
//      gSyzFwfuzzInputBuffer. The SyzAgentDxe driver prints both to
//      the debug console as a "SYZFWFUZZ trigger=... input=... size=..."
//      line. The first discovered triple is cached to a .syz-fwfuzz-cache
//      file in the workdir so subsequent runs skip the 45s boot.
//
//   2. Creates a SysV shmem segment for the fwsnap plugin.
//
//   3. Launches qemu-fwfuzz with:
//        -plugin libfwsnap.so,trigger=X,fuzz_addr=Y,fuzz_max=Z,shmid=N,
//               region=<DRAM range>,exit_trigger=X,loop=on
//      The libedgecov.so plugin is NOT loaded in this path — coverage
//      still comes from SyzCoverLib on the firmware side (which works
//      under TCG and whose PC ring lives in the snapshotted region).
//
//   4. Waits for the plugin to report SNAP_READY (the firmware has hit
//      SyzFwfuzzTrigger() and the plugin has captured a clean state).
//
//   5. Replaces the normal KVM fuzz loop's pokeAgent() with a fwsnap
//      RESTORE: host writes the program to the fuzz_input buffer, sends
//      RESTORE, waits for DONE status, then drains coverage from the
//      ivshmem cover ring (which was snapshotted+restored to empty).

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// tcgDiscoveryResult holds the runtime addresses discovered from a
// TCG boot. Cached in JSON at .syz-fwfuzz-cache so subsequent runs
// skip the slow pre-discovery boot.
type tcgDiscoveryResult struct {
	TriggerPc    uint64 `json:"trigger"`
	ExitPc       uint64 `json:"exit"`
	InputPhys    uint64 `json:"input"`
	InputSize    uint64 `json:"size"`
	ShadowBase   uint64 `json:"shadow,omitempty"`
	ShadowSize   uint64 `json:"shadow_size,omitempty"`
	DiscoveredAt string `json:"at"`
}

// discoverTcgAddresses runs qemu-fwfuzz in TCG mode with the SyzAgentDxe
// firmware and parses the SYZFWFUZZ marker line from the debug console.
// Caches the result on success.
func discoverTcgAddresses(cachePath, qemuBin, ovmfCode, ovmfVars, shmPath, debugLog string) (*tcgDiscoveryResult, error) {
	// Cache hit?
	if data, err := os.ReadFile(cachePath); err == nil {
		var r tcgDiscoveryResult
		if json.Unmarshal(data, &r) == nil && r.TriggerPc != 0 {
			fmt.Fprintf(os.Stderr, "[tcgsnap] cache hit: trigger=0x%x input=0x%x\n",
				r.TriggerPc, r.InputPhys)
			return &r, nil
		}
	}

	fmt.Fprintf(os.Stderr, "[tcgsnap] no cached discovery — booting OVMF in TCG (~60s)\n")
	// Truncate the debug log and shm.
	_ = os.Remove(debugLog)
	if f, err := os.Create(shmPath); err == nil {
		f.Truncate(256 << 20)
		f.Close()
	}

	// Discovery boot uses KVM when available: we only need to parse
	// the SYZFWFUZZ debug marker, and ASan-instrumented OVMF in TCG
	// takes 10+ minutes just to reach that point. DXE image load
	// addresses are deterministic between KVM and TCG for the same
	// OVMF build, so the discovered PCs are valid for the fwsnap run.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, qemuBin,
		"-machine", "q35,accel=kvm:tcg,smm=off",
		"-cpu", "host",
		"-m", "1024",
		"-nodefaults",
		"-no-reboot",
		"-nographic",
		"-serial", "null",
		"-drive", "if=pflash,format=raw,readonly=on,file="+ovmfCode,
		"-drive", "if=pflash,format=raw,file="+ovmfVars,
		"-debugcon", "file:"+debugLog,
		"-global", "isa-debugcon.iobase=0x402",
		"-object", fmt.Sprintf("memory-backend-file,id=syzcov,share=on,mem-path=%s,size=256M", shmPath),
		"-device", "ivshmem-plain,memdev=syzcov",
	)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start discovery qemu: %w", err)
	}
	// Poll debug log for the SYZFWFUZZ marker.
	deadline := time.Now().Add(3 * time.Minute)
	var result *tcgDiscoveryResult
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(debugLog); err == nil {
			if r := parseFwfuzzMarker(string(b)); r != nil {
				result = r
				break
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
	if result == nil {
		return nil, fmt.Errorf("SYZFWFUZZ marker never appeared in %s", debugLog)
	}
	result.DiscoveredAt = time.Now().Format(time.RFC3339)
	if data, err := json.MarshalIndent(result, "", "  "); err == nil {
		_ = os.WriteFile(cachePath, data, 0o644)
	}
	fmt.Fprintf(os.Stderr, "[tcgsnap] discovered trigger=0x%x input=0x%x size=0x%x\n",
		result.TriggerPc, result.InputPhys, result.InputSize)
	return result, nil
}

// parseFwfuzzMarker scans debug log text for the marker line emitted by
// SyzFwfuzzRegister() and returns the parsed addresses.
func parseFwfuzzMarker(text string) *tcgDiscoveryResult {
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "SYZFWFUZZ") {
			continue
		}
		r := &tcgDiscoveryResult{}
		for _, tok := range strings.Fields(line) {
			if strings.HasPrefix(tok, "trigger=0x") {
				fmt.Sscanf(tok, "trigger=0x%x", &r.TriggerPc)
			} else if strings.HasPrefix(tok, "exit=0x") {
				fmt.Sscanf(tok, "exit=0x%x", &r.ExitPc)
			} else if strings.HasPrefix(tok, "input=0x") {
				fmt.Sscanf(tok, "input=0x%x", &r.InputPhys)
			} else if strings.HasPrefix(tok, "size=0x") {
				fmt.Sscanf(tok, "size=0x%x", &r.InputSize)
			} else if strings.HasPrefix(tok, "shadow=0x") {
				fmt.Sscanf(tok, "shadow=0x%x", &r.ShadowBase)
			} else if strings.HasPrefix(tok, "shadow_size=0x") {
				fmt.Sscanf(tok, "shadow_size=0x%x", &r.ShadowSize)
			}
		}
		if r.TriggerPc != 0 && r.InputPhys != 0 && r.InputSize != 0 {
			return r
		}
	}
	return nil
}

// launchQemuTcgSnapshot starts qemu-fwfuzz in TCG mode with the
// fwsnap plugin attached. Returns the running qemu cmd, the fwsnap
// shmem handle, and the discovered trigger/input addresses.
func launchQemuTcgSnapshot(ctx context.Context, wp *workerPaths) (*exec.Cmd, *fwsnap, *tcgDiscoveryResult, error) {
	// 1. Discovery.
	cachePath := filepath.Join(wp.workdir, ".syz-fwfuzz-cache.json")
	discPath := filepath.Join(wp.workdir, "tcgsnap-discover.log")
	discShm := filepath.Join(wp.workdir, "tcgsnap-discover.shm")
	res, err := discoverTcgAddresses(cachePath, *flagQemuFwfuzz, *flagOvmfCode, wp.varsCopy, discShm, discPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("discovery: %w", err)
	}

	// 2. Allocate fwsnap shmem.
	fm := int(res.InputSize)
	if fm < 64<<10 {
		fm = 64 << 10
	}
	fs, err := newFwsnap(fm)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("newFwsnap: %w", err)
	}

	// 3. Build qemu command.
	// The exit_trigger PC must be DIFFERENT from trigger_addr, otherwise
	// the plugin treats every re-entry as an immediate exit without
	// running the function body. The firmware prints both trigger and
	// exit PCs in the SYZFWFUZZ marker line; we use what it reports.
	exitPc := res.ExitPc
	if exitPc == 0 {
		// Legacy fallback: use an offset from the objdump disassembly.
		exitPc = res.TriggerPc + 0x74
	}
	if *flagExitPc != 0 {
		exitPc = *flagExitPc
	}

	// fwsnap must snapshot/restore the RAM regions that the guest
	// modifies between iterations. For OVMF on q35 with 1 GiB RAM,
	// DXE drivers live in low DRAM (typically 0x3C000000-0x3FFFFFFF),
	// the stack and pool lie alongside them, and the ivshmem BAR is
	// mapped higher (around 0xC000000000). Attempting to cover the
	// entire 0-1 GiB hits reserved ranges (BIOS ROM, MMIO) and the
	// plugin returns INVALID_ADDRESS.
	//
	// Restrict to 128 MiB of DXE memory straddling the SyzAgentDxe
	// load address. That's the firmware's working set for the
	// SyzFwfuzzTrigger dispatch path: the input buffer, the cover
	// ring (which is in ivshmem so we cover that separately), and
	// SyzAgentDxe's bss/stack. Adjust if your build loads drivers
	// outside this window.
	const regionBase = 0x3C000000
	const regionSize = 0x04000000 // 64 MiB
	// loop=off: with loop_mode on, the plugin auto-restores after DONE,
	// which turns the one-shot init-time call to SyzFwfuzzTrigger() from
	// SyzFwfuzzRegister() into an infinite restore loop that prevents the
	// firmware from ever finishing init. With loop=off, the plugin stops
	// at DONE and waits for the host to send RESTORE explicitly.
	snapPlugin := fmt.Sprintf(
		"contrib/plugins/libfwsnap.so,trigger=0x%x,fuzz_addr=0x%x,fuzz_max=%d,shmid=%d,"+
			"region=0x%x:0x%x,exit_trigger=0x%x,loop=off,max_blocks=2000000",
		res.TriggerPc, res.InputPhys, fm, fs.ShmId(),
		regionBase, regionSize, exitPc)
	// The ASan shadow region is NOT passed via the region= plugin arg.
	// OVMF's PCI enumeration assigns the ivshmem BAR a different
	// physical address under KVM vs TCG (seen empirically: KVM placed
	// it at 0x380000000000, TCG at 0xC000000000). Our KVM-driven
	// discovery boot therefore reports a shadow base that the TCG
	// fuzz run has never heard of, and save_memory_regions would fail
	// on the wrong address. Instead, we monitor the TCG run's own
	// debug log for the SYZFWFUZZ marker (see waitForShadowAndPublish
	// below) and write the correct shadow_base / shadow_size into
	// the fwsnap control shmem. The plugin picks these up in
	// do_snapshot() and registers a dynamic region for them.

	pluginDbg := filepath.Join(wp.workdir, "fwsnap-plugin.log")
	args := []string{
		// Single-threaded TCG is required: the fwsnap plugin's
		// do_restore() calls qemu_plugin_set_pc() → cpu_loop_exit()
		// → cpu_interrupt(), which asserts that the Big QEMU Lock
		// (BQL) is held. In MTTCG the callback runs on a TCG worker
		// thread that doesn't hold BQL; in single-threaded TCG the
		// sole TCG thread IS the iothread, so BQL is always held.
		"-machine", "q35,smm=off",
		"-accel", "tcg,thread=single",
		"-cpu", "max",
		"-m", "1024",
		"-nodefaults",
		"-no-reboot",
		"-nographic",
		"-serial", "null",
		"-drive", "if=pflash,format=raw,readonly=on,file=" + *flagOvmfCode,
		"-drive", "if=pflash,format=raw,file=" + wp.varsCopy,
		"-debugcon", "file:" + wp.debugLog,
		"-global", "isa-debugcon.iobase=0x402",
		"-object", fmt.Sprintf("memory-backend-file,id=syzcov,share=on,mem-path=%s,size=256M", wp.shmem),
		"-device", "ivshmem-plain,memdev=syzcov",
		"-plugin", snapPlugin,
		"-D", pluginDbg, "-d", "plugin",
	}

	// Plugins use relative paths, so chdir into the plugin build dir.
	pluginDir := filepath.Dir(*flagQemuFwfuzz)
	cmd := exec.CommandContext(ctx, *flagQemuFwfuzz, args...)
	cmd.Dir = pluginDir
	// Capture stdout/stderr. Plugin messages via qemu_plugin_outs() go
	// to the -D file (pluginDbg above); fprintf(stderr) goes here.
	stderrLog, err := os.Create(filepath.Join(wp.workdir, "fwsnap-qemu-stderr.log"))
	if err == nil {
		cmd.Stdout = stderrLog
		cmd.Stderr = stderrLog
	} else {
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Start(); err != nil {
		fs.Close()
		return nil, nil, nil, fmt.Errorf("start fwsnap qemu: %w", err)
	}

	// 3b. Tail the TCG run's own debug log until we see the SYZFWFUZZ
	//     marker, then publish the ACCURATE shadow region through the
	//     fwsnap control shmem. This has to come from *this* run's log
	//     because OVMF's PCI enumeration places the ivshmem BAR at a
	//     different PCI64 address under KVM vs TCG; the cached
	//     discovery (which runs under KVM for speed) will have
	//     reported the KVM-side address, which is wrong here.
	go func() {
		deadline := time.Now().Add(25 * time.Minute)
		for time.Now().Before(deadline) {
			if data, err := os.ReadFile(wp.debugLog); err == nil {
				if r := parseFwfuzzMarker(string(data)); r != nil {
					if r.ShadowBase != 0 && r.ShadowSize != 0 {
						fs.SetShadowRegion(r.ShadowBase, r.ShadowSize)
						fmt.Fprintf(os.Stderr,
							"[tcgsnap] published runtime shadow 0x%x:0x%x from TCG debug log\n",
							r.ShadowBase, r.ShadowSize)
					}
					return
				}
			}
			time.Sleep(500 * time.Millisecond)
		}
	}()

	// 4. Wait for the plugin to report SNAP_READY (snapshot taken but
	//    the trigger body hasn't reached the exit PC yet) OR DONE (the
	//    snapshot was taken and the init-time call to SyzFwfuzzTrigger
	//    from SyzFwfuzzRegister already ran through to the exit nop).
	//    Either is a valid "ready to fuzz" state: do_restore() is gated
	//    on snapshot_taken, not on the current status.
	//
	// ASan-instrumented OVMF under TCG is extraordinarily slow to
	// boot (every memory access becomes a TCG helper call to
	// __asan_load/store), so budget generously — 20 minutes for
	// ASan builds versus ~1 minute for plain NOOPT. We pay this
	// only once per run.
	fmt.Fprintf(os.Stderr, "[tcgsnap] waiting for SNAP_READY/DONE (TCG boot in progress)\n")
	if _, err := fs.WaitStatus(20*time.Minute, fwsnapStatusSnapReady, fwsnapStatusDone); err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		fs.Close()
		return nil, nil, nil, fmt.Errorf("wait SNAP_READY: %w", err)
	}
	fmt.Fprintf(os.Stderr, "[tcgsnap] SNAP_READY — fuzz loop can begin\n")
	return cmd, fs, res, nil
}

// runSnapshotProgram is the per-iteration hook for TCG snapshot mode.
// It replaces the pokeAgent + waitForAck + drainCoverage sequence of
// the KVM path with a fwsnap RESTORE + wait + drain.
func runSnapshotProgram(fs *fwsnap, prog *program, shmemData []byte, inputPhys uint64, execTimeout time.Duration) (ok bool, progPCs []uint64) {
	// Build the wire buffer: magic + ncalls + call records, same as
	// what the normal doorbell poke would write.
	buf := make([]byte, 8+len(prog.Wire))
	// magic
	buf[0] = 0x45
	buf[1] = 0x5A
	buf[2] = 0x59
	buf[3] = 0x53
	// ncalls
	buf[4] = byte(prog.NumCalls)
	buf[5] = byte(prog.NumCalls >> 8)
	buf[6] = byte(prog.NumCalls >> 16)
	buf[7] = byte(prog.NumCalls >> 24)
	copy(buf[8:], prog.Wire)

	// Set the fuzz input + inject address for the plugin.
	if err := fs.SetFuzzInput(inputPhys, buf); err != nil {
		return false, nil
	}
	// Zero the cover ring before the restore so we get per-iteration PCs.
	// The ivshmem region is in the fwsnap snapshot, so the plugin will
	// restore the cover count to whatever it was at snapshot time.
	// That's either 0 (if the initial trigger ran cleanly) or a small
	// residue. Zero it just in case.
	writeU32(shmemData, edk2OffCoverCount, 0)
	// Use the full per-iteration budget for SendRestore. In TCG the
	// guest may be in HLT between iterations waiting on a timer IRQ;
	// the plugin can't service commands until a TB runs, so a tight
	// 2s timeout here produces spurious failures.
	if err := fs.SendRestore(execTimeout); err != nil {
		return false, nil
	}
	// Wait for the plugin to report DONE.
	st, err := fs.WaitStatus(execTimeout, fwsnapStatusDone)
	if err != nil || st != fwsnapStatusDone {
		return false, nil
	}
	// Drain coverage PCs from the ivshmem cover ring (populated by
	// SyzCoverLib during the dispatch).
	progPCs = drainCoverageSlice(shmemData)
	return true, progPCs
}
