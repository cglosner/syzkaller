// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// fwsnap_edk2.go — helpers for launching edk2/amd64 VMs under the
// cglosner/qemu-fwfuzz plugin (libfwsnap.so) for snapshot-based
// firmware fuzzing. Activated via Config.TcgSnapshot=true.
//
// The plugin takes a snapshot at the first entry to SyzFwfuzzTrigger
// (the synchronous dispatch shim in SyzAgentDxe) and then lets the
// host replace each iteration with a register+memory rollback via a
// RESTORE command written to a SysV shmem control region. This gives
// ~10-30× faster fuzz iterations vs KVM cold restart, and survives
// even ASan-instrumented OVMF builds.
//
// The standalone reference driver lives in tools/syz-edk2-fuzz. This
// file provides the minimum pieces vm/qemu.go needs to fold that
// driver into a syz-manager VM: discovery, shmem allocation, plugin
// arg builder, and the shadow-publish goroutine.

package qemu

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Wire layout of the fwsnap SysV control shmem header. Must match
// FwSnapControl in contrib/plugins/fwsnap.c exactly.
const (
	fwsnapHeaderSize = 64

	fwsnapOffCommand      = 0
	fwsnapOffStatus       = 1
	fwsnapOffFuzzInputAdr = 8
	fwsnapOffFuzzInputLen = 16
	fwsnapOffIterBlocks   = 24
	fwsnapOffExitReason   = 32
	fwsnapOffShadowBase   = 40
	fwsnapOffShadowSize   = 48
	fwsnapOffFuzzData     = 64

	fwsnapStatusIdle      = 0
	fwsnapStatusSnapReady = 2
	fwsnapStatusRestored  = 3
	fwsnapStatusDone      = 4
)

// fwsnapDiscovery holds the runtime addresses published by the
// firmware in its SYZFWFUZZ debug-con marker line. Trigger/exit/input
// are stable across accelerators for a given OVMF build; shadow lives
// at different PCI64 addresses under KVM vs TCG, so we republish it
// from the TCG run's own debug log at launch time.
type fwsnapDiscovery struct {
	TriggerPc    uint64 `json:"trigger"`
	ExitPc       uint64 `json:"exit"`
	InputPhys    uint64 `json:"input"`
	InputSize    uint64 `json:"size"`
	ShadowBase   uint64 `json:"shadow,omitempty"`
	ShadowSize   uint64 `json:"shadow_size,omitempty"`
	DiscoveredAt string `json:"at"`
}

// fwsnapShm is a SysV shmem segment attached to the host used as the
// fwsnap plugin's control region. The plugin reads host commands and
// publishes status bytes here; the host reads status, writes the
// fuzz_input buffer, and sets shadow_base/shadow_size after parsing
// the TCG-side SYZFWFUZZ marker.
type fwsnapShm struct {
	id   int
	mem  []byte
	fmax int
}

// newFwsnapShm creates a SysV shmem segment big enough for the
// control header + a fuzz_input buffer of fuzzMax bytes.
func newFwsnapShm(fuzzMax int) (*fwsnapShm, error) {
	total := fwsnapHeaderSize + fuzzMax
	id, err := unix.SysvShmGet(unix.IPC_PRIVATE, total, 0o666|unix.IPC_CREAT)
	if err != nil {
		return nil, fmt.Errorf("SysvShmGet: %w", err)
	}
	mem, err := unix.SysvShmAttach(id, 0, 0)
	if err != nil {
		_, _ = unix.SysvShmCtl(id, unix.IPC_RMID, nil)
		return nil, fmt.Errorf("SysvShmAttach(%d): %w", id, err)
	}
	for i := range mem {
		mem[i] = 0
	}
	return &fwsnapShm{id: id, mem: mem, fmax: fuzzMax}, nil
}

// Close detaches and removes the shmem segment.
func (s *fwsnapShm) Close() {
	if s == nil || s.mem == nil {
		return
	}
	_ = unix.SysvShmDetach(s.mem)
	_, _ = unix.SysvShmCtl(s.id, unix.IPC_RMID, nil)
	s.mem = nil
}

// SetShadowRegion publishes the ASan shadow region base/size to the
// plugin. The plugin's do_snapshot picks these up before saving, so
// subsequent restores roll shadow state back.
func (s *fwsnapShm) SetShadowRegion(base, size uint64) {
	if s == nil || s.mem == nil {
		return
	}
	binary.LittleEndian.PutUint64(s.mem[fwsnapOffShadowBase:], base)
	binary.LittleEndian.PutUint64(s.mem[fwsnapOffShadowSize:], size)
}

// ReadStatus reads the plugin status byte.
func (s *fwsnapShm) ReadStatus() uint8 {
	if s == nil || s.mem == nil {
		return 0
	}
	return s.mem[fwsnapOffStatus]
}

// parseFwfuzzMarker scans a debug console log for the stable
// SYZFWFUZZ line emitted by SyzFwfuzzRegister() and returns the
// parsed addresses. Returns nil if no complete marker is present.
func parseFwfuzzMarker(text string) *fwsnapDiscovery {
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "SYZFWFUZZ") {
			continue
		}
		r := &fwsnapDiscovery{}
		for _, tok := range strings.Fields(line) {
			switch {
			case strings.HasPrefix(tok, "trigger=0x"):
				fmt.Sscanf(tok, "trigger=0x%x", &r.TriggerPc)
			case strings.HasPrefix(tok, "exit=0x"):
				fmt.Sscanf(tok, "exit=0x%x", &r.ExitPc)
			case strings.HasPrefix(tok, "input=0x"):
				fmt.Sscanf(tok, "input=0x%x", &r.InputPhys)
			case strings.HasPrefix(tok, "size=0x"):
				fmt.Sscanf(tok, "size=0x%x", &r.InputSize)
			case strings.HasPrefix(tok, "shadow=0x"):
				fmt.Sscanf(tok, "shadow=0x%x", &r.ShadowBase)
			case strings.HasPrefix(tok, "shadow_size=0x"):
				fmt.Sscanf(tok, "shadow_size=0x%x", &r.ShadowSize)
			}
		}
		if r.TriggerPc != 0 && r.InputPhys != 0 && r.InputSize != 0 {
			return r
		}
	}
	return nil
}

// discoverFwsnapAddresses runs a one-shot boot of OVMF under the
// SAME accelerator the main fwsnap run will use (single-thread TCG),
// tails the debug console for the SYZFWFUZZ marker, caches the
// result in JSON, and returns the parsed addresses.
//
// Using KVM here is tempting for speed but wrong: OVMF's DXE image
// loader places SyzAgentDxe at different runtime addresses under KVM
// vs TCG (seen empirically: trigger=0x3E87A9CA under KVM,
// 0x3E47A9CA under TCG — 4 MiB apart). Ditto the ivshmem BAR that
// hosts the ASan shadow. If we discover under KVM and then run
// under TCG, the plugin's trigger_addr never matches pc in
// vcpu_tb_exec, no snapshot is taken, and every RESTORE command is
// a silent no-op.
//
// For ASan-instrumented builds the first-boot cost is 5-10 minutes;
// after that the JSON cache short-circuits subsequent starts, so
// the cost is paid once per OVMF build.
func discoverFwsnapAddresses(cachePath, qemuBin, ovmfCode, ovmfVars, shmPath, debugLog string) (*fwsnapDiscovery, error) {
	if data, err := os.ReadFile(cachePath); err == nil {
		var r fwsnapDiscovery
		if json.Unmarshal(data, &r) == nil && r.TriggerPc != 0 {
			return &r, nil
		}
	}

	_ = os.Remove(debugLog)
	if f, err := os.Create(shmPath); err == nil {
		f.Truncate(256 << 20)
		f.Close()
	}

	//
	// Discovery VM runs once per manager startup to capture the
	// SyzFwfuzzTrigger PC and shadow base. Must include the same
	// target devices the fuzz VM uses so the drivers actually bind
	// and install protocols (otherwise every protocol-method syscall
	// hits EFI_NOT_FOUND at runtime).
	//
	// The fuzz disk lives next to debugLog in the template dir.
	fuzzDiskPath := filepath.Join(filepath.Dir(debugLog), "fuzz-disk.img")
	args := []string{
		"-machine", "q35,smm=off",
		"-accel", "tcg,thread=single",
		"-cpu", "qemu64",
		"-m", "1024",
		"-nodefaults",
		"-no-reboot",
		"-nographic",
		"-serial", "null",
		"-drive", "if=pflash,format=raw,readonly=on,file=" + ovmfCode,
		"-drive", "if=pflash,format=raw,file=" + ovmfVars,
		"-debugcon", "file:" + debugLog,
		"-global", "isa-debugcon.iobase=0x402",
		"-object", fmt.Sprintf("memory-backend-file,id=syzcov,share=on,mem-path=%s,size=256M", shmPath),
		"-device", "ivshmem-plain,memdev=syzcov",
		// virtio-net-pci with usermode slirp backend — no tap/bridge
		// required. Unlocks SNP/MNP/ARP/IP4/UDP4/TCP4/DHCP4 drivers.
		"-netdev", "user,id=net0",
		"-device", "virtio-net-pci,netdev=net0",
	}
	// virtio-blk-pci with a FAT32-formatted RAM-backed image —
	// unlocks BlockIo/DiskIo/PartitionDxe/Fat/SimpleFs drivers.
	if _, err := os.Stat(fuzzDiskPath); err == nil {
		args = append(args,
			"-drive", "if=none,id=disk0,format=raw,file="+fuzzDiskPath,
			"-device", "virtio-blk-pci,drive=disk0")
	}
	cmd := exec.Command(qemuBin, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start discovery qemu: %w", err)
	}
	// TCG + ASan OVMF takes 5-10 minutes to reach the marker under
	// normal load. With target drivers (VariableRuntimeDxe,
	// FatPkg, etc.) opted into `-fsanitize=kernel-address`, the
	// per-access shadow-load overhead stacks up and boot can take
	// 30+ minutes on a slower host. Non-ASan builds hit the marker
	// in ~60 seconds.
	deadline := time.Now().Add(45 * time.Minute)
	var result *fwsnapDiscovery
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(debugLog); err == nil {
			if r := parseFwfuzzMarker(string(b)); r != nil {
				result = r
				break
			}
		}
		time.Sleep(500 * time.Millisecond)
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
	return result, nil
}

// watchDebugLogForShadow tails the TCG run's debug-con log and
// publishes the runtime shadow region into the fwsnap control shmem
// as soon as the SYZFWFUZZ marker appears. The plugin's do_snapshot
// reads those fields before saving the first snapshot.
//
// It ALSO parses "Loading driver at 0x..." lines to build a runtime
// module address map for the coverage backend (see
// backend.SetEdk2RuntimeAddrs). Without that map, module.Addr stays
// at 0 and runtime PCs from instrumented drivers don't fall into
// any module's range, leaving /cover empty.
//
// Runs for up to 25 minutes (enough for even the slowest ASan+TCG
// boot) and exits once the shadow is published.
func watchDebugLogForShadow(debugLog string, shm *fwsnapShm, logger io.Writer,
	publishAddrs func(map[string]uint64)) {
	deadline := time.Now().Add(25 * time.Minute)
	shadowPublished := false
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(debugLog); err == nil {
			if !shadowPublished {
				if r := parseFwfuzzMarker(string(data)); r != nil {
					if r.ShadowBase != 0 && r.ShadowSize != 0 {
						shm.SetShadowRegion(r.ShadowBase, r.ShadowSize)
						if logger != nil {
							fmt.Fprintf(logger,
								"fwsnap: published runtime shadow 0x%x:0x%x\n",
								r.ShadowBase, r.ShadowSize)
						}
					}
					shadowPublished = true
				}
			}
			// Publish runtime module addresses on every pass (the
			// map only grows as new drivers load). Doing this only
			// once, at shadow-publish time, misses drivers loaded
			// later in BDS.
			if publishAddrs != nil {
				if m := parseEdk2LoadingDrivers(string(data)); len(m) > 0 {
					publishAddrs(m)
				}
			}
		}
		if shadowPublished {
			// Shadow found — do one final module parse and exit.
			if data, err := os.ReadFile(debugLog); err == nil && publishAddrs != nil {
				if m := parseEdk2LoadingDrivers(string(data)); len(m) > 0 {
					publishAddrs(m)
				}
			}
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// parseEdk2LoadingDrivers extracts image name → runtime base address
// pairs from the edk2 debug-con log. The dispatcher prints one of:
//
//	Loading driver at 0x000<addr> EntryPoint=0x000<ep> <Name>.efi
//	Loading PEIM at   0x000<addr> EntryPoint=0x000<ep> <Name>.efi
//
// We match both because DxeCore is announced as "Loading PEIM at" (it
// starts life in the PEI phase and gets re-dispatched as the DXE core),
// but its code is instrumented with -fsanitize-coverage=trace-pc like
// every other DXE module. Without matching PEIM lines, cover PCs in
// DxeCore's address range (~0x3fe2f000+) are reported by the executor
// but the manager fails to attribute them to any module and /cover
// rejects the whole profile with "PCs do not have matching coverage
// callbacks".
//
// The separate "Loading DXE CORE at …" line is ignored because it
// lacks the trailing ".efi Name" token; the earlier PEIM line carries
// the same address and name.
func parseEdk2LoadingDrivers(text string) map[string]uint64 {
	out := map[string]uint64{}
	for _, line := range strings.Split(text, "\n") {
		var off int
		switch {
		case strings.Contains(line, "Loading driver at "):
			off = strings.Index(line, "Loading driver at ") + len("Loading driver at ")
		case strings.Contains(line, "Loading PEIM at "):
			off = strings.Index(line, "Loading PEIM at ") + len("Loading PEIM at ")
		default:
			continue
		}
		rest := line[off:]
		var addr uint64
		if _, err := fmt.Sscanf(rest, "0x%x", &addr); err != nil {
			continue
		}
		// Extract the trailing <Name>.efi token.
		efi := strings.Index(rest, ".efi")
		if efi < 0 {
			continue
		}
		// Walk backwards from .efi to the last space.
		sp := strings.LastIndexByte(rest[:efi], ' ')
		if sp < 0 {
			continue
		}
		name := rest[sp+1 : efi]
		out[name] = addr
	}
	return out
}

// buildFwsnapPluginArg renders the -plugin argument for qemu-fwfuzz
// based on discovered addresses + SysV shmid. A fixed 64 MiB DXE
// working-set region at 0x3c000000 is included (covers SyzAgentDxe
// bss/stack + the fuzz_input buffer + early pool allocations). The
// shadow region is added dynamically by the plugin when the host
// writes shadow_base/shadow_size into the control shmem (see
// watchDebugLogForShadow).
func buildFwsnapPluginArg(res *fwsnapDiscovery, shmid int, pluginRelPath string) string {
	const regionBase = 0x3C000000
	const regionSize = 0x04000000 // 64 MiB
	fuzzMax := int(res.InputSize)
	if fuzzMax < 64<<10 {
		fuzzMax = 64 << 10
	}
	return fmt.Sprintf(
		"%s,trigger=0x%x,fuzz_addr=0x%x,fuzz_max=%d,shmid=%d,"+
			"region=0x%x:0x%x,exit_trigger=0x%x,loop=off,max_blocks=2000000",
		pluginRelPath,
		res.TriggerPc, res.InputPhys, fuzzMax, shmid,
		regionBase, regionSize, res.ExitPc,
	)
}

// fwsnapPluginDir returns the directory containing libfwsnap.so
// relative to the qemu-fwfuzz binary. The plugin is always installed
// alongside qemu-system-x86_64 under contrib/plugins in the
// cglosner/qemu-fwfuzz build tree.
func fwsnapPluginDir(qemuFwfuzz string) string {
	return filepath.Dir(qemuFwfuzz)
}

// stripEdk2HeavyDevices filters the "-device"/"-drive"/"-netdev"/
// "-chardev"/"-global" chunks from the default edk2/amd64 QemuArgs
// that aren't needed for fwsnap snapshot fuzzing. Under TCG these
// devices multiply boot time, and the snapshot path doesn't exercise
// them — SyzAgentDispatch only needs the ivshmem BAR + the debug
// console.
//
// We keep:
//   - the ivshmem-plain device (syzcov)
//   - the memory-backend-file object backing ivshmem
//   - -debugcon (SyzAgentDxe marker channel)
//   - -global isa-debugcon.iobase=0x402
//   - -nodefaults / -no-reboot / -nographic etc (framework)
//
// Everything else (virtio-net, virtio-blk, NVMe, AHCI, SDHCI,
// xHCI, VGA, e1000, isa-serial, etc.) gets dropped. The fwsnap
// snapshot is at SyzFwfuzzTrigger entry so those devices are
// irrelevant to the workload.
func stripEdk2HeavyDevices(qargs string) string {
	// Split on unquoted spaces. The template uses simple
	// space-separated args; no shell quoting needed.
	parts := strings.Fields(qargs)
	out := make([]string, 0, len(parts))
	skip := 0
	//
	// Keep virtio-net-pci and virtio-blk-pci — they unlock ~150
	// syscalls worth of coverage (Snp/Mnp/Ip4/Tcp4/Udp4/Dhcp4/
	// BlockIo/DiskIo/Partition/Fat/SimpleFs). The earlier attempt
	// to keep them stalled boot in PciBusDxe under TCG+ASan, but
	// we've now carved PciBusDxe + PciHostBridgeDxe out of ASan
	// (see MdeModulePkg/Bus/Pci/... per-component overrides in
	// OvmfPkgX64.dsc), so PCI enumeration runs at native speed.
	// The target drivers (Ip4Dxe, Fat, etc.) remain ASan-
	// instrumented.
	//
	// Still stripped: VGA (no fuzz value), AHCI/IDE/NVMe/SCSI (virtio-
	// blk covers the same BlockIo surface; extra controllers just
	// multiply boot cost), USB/xHCI (few unique bugs, huge TCG boot
	// cost), SD, isa-serial.
	//
	heavyDevs := []string{
		"VGA",
		"ich9-ahci",
		"ide-hd",
		"nvme,",
		"qemu-xhci",
		"usb-tablet",
		"usb-kbd",
		"e1000",
		"sdhci-pci",
		"sd-card",
		"isa-serial",
	}
	heavyDriveIDs := []string{
		"id=sata0",
		"id=nvme0",
		"id=sddrv",
	}
	heavyNetdevs := []string{
		"id=net1",
	}
	heavyChardevs := []string{
		"id=ser0",
	}
	for i, p := range parts {
		if skip > 0 {
			skip--
			continue
		}
		switch p {
		case "-device":
			if i+1 < len(parts) {
				val := parts[i+1]
				for _, d := range heavyDevs {
					if strings.Contains(val, d) {
						skip = 1
						goto next
					}
				}
			}
		case "-drive":
			if i+1 < len(parts) {
				val := parts[i+1]
				for _, d := range heavyDriveIDs {
					if strings.Contains(val, d) {
						skip = 1
						goto next
					}
				}
			}
		case "-netdev":
			if i+1 < len(parts) {
				val := parts[i+1]
				for _, d := range heavyNetdevs {
					if strings.Contains(val, d) {
						skip = 1
						goto next
					}
				}
			}
		case "-chardev":
			if i+1 < len(parts) {
				val := parts[i+1]
				for _, d := range heavyChardevs {
					if strings.Contains(val, d) {
						skip = 1
						goto next
					}
				}
			}
		}
		out = append(out, p)
	next:
	}
	return strings.Join(out, " ")
}
