// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-edk2-smi-fuzz is a userspace SMI callout fuzzer for OVMF/EDK2.
//
// It boots a minimal Linux guest on top of an OVMF build with SMM enabled
// (SMM_REQUIRE=TRUE), and drives an in-guest userspace runner that:
//
//   - mmaps an ivshmem-plain region we set up at the host side as the
//     fuzzer wire channel
//   - reads SMI command bundles from that region
//   - primes attacker-controlled bytes into specific physical addresses
//     via /dev/mem (the SMM communication buffer + any callout pointers)
//   - issues `outb val 0xB2` (the APMC port) under iopl(3) to trigger
//     the SMI
//   - acks back via the same shmem doorbell so the host can move on
//
// The host side here is intentionally a near-clone of the SyzAgent
// transport in tools/syz-edk2-fuzz, so we share the same wire-format
// constants and the same `prog`-package code path for grammar-driven
// generation. The SMI program grammar (sys/edk2_smi/edk2_smi.txt) is
// not yet checked in; until then `-only-blind` generates random bundles.
//
// See ./README.md for the architecture overview and how to put together
// the guest initramfs.

package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"
)

// Wire-format constants. The first 0x200000 bytes of the ivshmem region
// mirror the SyzAgent control layout (magic + ncalls + payload + doorbell
// + cover ring) so the guest runner can parse it without having to learn
// a different protocol; everything past 0x200000 is unused for now and
// reserved for a future SMM coverage feedback channel.
const (
	smiMagic           uint32 = 0x53595A53 // 'SYZS'
	smiOffMagic        uint32 = 0x0000
	smiOffNcalls       uint32 = 0x0004
	smiOffCalls        uint32 = 0x0008
	smiOffHostSeq      uint32 = 0x1000
	smiOffGuestSeq     uint32 = 0x1004
	smiOffGuestStatus  uint32 = 0x1008
	smiMaxCalls               = 32
	smiMaxProgramBytes        = 0x1000 - 8 // smiOffHostSeq - smiOffCalls
	smiShmemSize       int64  = 256 << 20

	// SMI command-bundle record kinds. Each record in a bundle is
	// (kind:u32, size:u32, payload[size-8]).
	smiKindWritePhys = 1 // payload: u64 phys_addr, u32 len, u8 data[len]
	smiKindOutb      = 2 // payload: u8 port_value
	smiKindReadPhys  = 3 // payload: u64 phys_addr, u32 len  (for status)
)

var (
	flagOvmfCode    = flag.String("ovmf-code", "", "OVMF_CODE.fd path (required)")
	flagOvmfVars    = flag.String("ovmf-vars", "", "OVMF_VARS.fd path (required)")
	flagKernel      = flag.String("kernel", "", "Linux bzImage path (required)")
	flagInitrd      = flag.String("initrd", "", "initramfs.cpio.gz path (required)")
	flagDebugLog    = flag.String("ovmf-debug-log", "", "OVMF debug-con output path")
	flagShmem       = flag.String("shmem", "/tmp/syz-edk2-smi.shm", "ivshmem backing file path")
	flagWorkdir    = flag.String("workdir", "/tmp/syz-edk2-smi-work", "per-VM workdir")
	flagDuration    = flag.Duration("duration", 60*time.Second, "campaign length")
	flagSeed        = flag.Int64("seed", time.Now().UnixNano(), "random seed")
	flagQemu        = flag.String("qemu", "qemu-system-x86_64", "qemu binary")
	flagPokeTimeout = flag.Duration("poke-timeout", 5*time.Second, "per-bundle ack timeout")
	flagOnlyBlind   = flag.Bool("only-blind", true, "use blind random generator (until sys/edk2_smi/ exists)")
	flagVerbose     = flag.Bool("v", false, "verbose: print every poke")
)

type stats struct {
	Bundles      atomic.Uint64
	Acks         atomic.Uint64
	Timeouts     atomic.Uint64
	GuestErrors  atomic.Uint64
	StartedAt    time.Time
	BootDuration time.Duration
}

type runResult struct {
	Bundles         uint64   `json:"bundles"`
	Acks            uint64   `json:"acks"`
	Timeouts        uint64   `json:"timeouts"`
	GuestErrors     uint64   `json:"guest_errors"`
	DurationSec     float64  `json:"duration_sec"`
	BootDurationSec float64  `json:"boot_duration_sec"`
	CrashTitles     []string `json:"crash_titles"`
	OK              bool     `json:"ok"`
}

type bundle struct {
	NumCalls int
	Wire     []byte
}

func main() {
	flag.Parse()
	for _, p := range []struct {
		name, val string
	}{
		{"ovmf-code", *flagOvmfCode},
		{"ovmf-vars", *flagOvmfVars},
		{"kernel", *flagKernel},
		{"initrd", *flagInitrd},
	} {
		if p.val == "" {
			fmt.Fprintf(os.Stderr, "-%s is required\n", p.name)
			os.Exit(2)
		}
	}
	if err := os.MkdirAll(*flagWorkdir, 0o755); err != nil {
		fail("mkdir workdir: %v", err)
	}
	if *flagDebugLog == "" {
		*flagDebugLog = filepath.Join(*flagWorkdir, "edk2-debug.log")
	}
	varsCopy := filepath.Join(*flagWorkdir, "OVMF_VARS.fd")
	if err := copyFile(*flagOvmfVars, varsCopy); err != nil {
		fail("copy vars: %v", err)
	}
	if err := truncateShmem(*flagShmem, smiShmemSize); err != nil {
		fail("create shmem: %v", err)
	}
	shmem, err := mmapFile(*flagShmem, smiShmemSize)
	if err != nil {
		fail("mmap shmem: %v", err)
	}
	defer shmem.Close()
	// Reset doorbell + magic.
	zeroSlice(shmem.Data[smiOffMagic : smiOffCalls+0x100])
	zeroSlice(shmem.Data[smiOffHostSeq : smiOffHostSeq+12])
	writeU32(shmem.Data, smiOffMagic, smiMagic)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startBoot := time.Now()
	qemu := launchQemu(ctx, varsCopy)
	defer func() {
		_ = qemu.Process.Kill()
		_, _ = qemu.Process.Wait()
	}()
	if err := waitForGuest(shmem.Data); err != nil {
		dumpDebugTail(*flagDebugLog, 80)
		fail("guest not ready: %v", err)
	}
	st := &stats{StartedAt: time.Now(), BootDuration: time.Since(startBoot)}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; cancel() }()

	rng := rand.New(rand.NewSource(*flagSeed))
	deadline := time.Now().Add(*flagDuration)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
		default:
		}
		var b *bundle
		if *flagOnlyBlind {
			b = generateBlindBundle(rng)
		} else {
			// TODO: plug sys/edk2_smi/ grammar here.
			b = generateBlindBundle(rng)
		}
		st.Bundles.Add(1)
		ok := pokeGuest(shmem.Data, b, *flagPokeTimeout)
		if !ok {
			st.Timeouts.Add(1)
			if *flagVerbose {
				fmt.Fprintf(os.Stderr, "[poke %d] TIMEOUT ncalls=%d\n",
					st.Bundles.Load(), b.NumCalls)
			}
			continue
		}
		if readU32(shmem.Data, smiOffGuestStatus) != 0 {
			st.GuestErrors.Add(1)
		} else {
			st.Acks.Add(1)
		}
	}

	cancel()
	_ = qemu.Process.Kill()
	_, _ = qemu.Process.Wait()
	titles := scanDebugLog(*flagDebugLog)
	res := runResult{
		Bundles:         st.Bundles.Load(),
		Acks:            st.Acks.Load(),
		Timeouts:        st.Timeouts.Load(),
		GuestErrors:     st.GuestErrors.Load(),
		DurationSec:     time.Since(st.StartedAt).Seconds(),
		BootDurationSec: st.BootDuration.Seconds(),
		CrashTitles:     titles,
		OK:              st.Acks.Load() > 0,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(&res)
}

// generateBlindBundle emits a single random WritePhys + Outb pair. This
// is the fallback path until we ship sys/edk2_smi/edk2_smi.txt.
func generateBlindBundle(rng *rand.Rand) *bundle {
	var buf []byte
	num := 0

	// Random WritePhys: pick a 16-byte chunk in the OVMF SMM
	// communication buffer area. The exact address depends on the
	// platform; the runner does NOT enforce that the address must
	// be the SMM comm buffer — it just trusts the bundle.
	addr := uint64(0x800000) + uint64(rng.Intn(0x10000))
	dataLen := 8 + rng.Intn(56)
	data := make([]byte, dataLen)
	for i := range data {
		data[i] = byte(rng.Intn(256))
	}
	wp := make([]byte, 8+8+4+dataLen)
	binary.LittleEndian.PutUint32(wp[0:], smiKindWritePhys)
	binary.LittleEndian.PutUint32(wp[4:], uint32(len(wp)))
	binary.LittleEndian.PutUint64(wp[8:], addr)
	binary.LittleEndian.PutUint32(wp[16:], uint32(dataLen))
	copy(wp[20:], data)
	buf = append(buf, wp...)
	num++

	// Outb to APMC: pick a random byte.
	cmd := byte(rng.Intn(256))
	ob := make([]byte, 8+1+3) // 4-byte aligned padding
	binary.LittleEndian.PutUint32(ob[0:], smiKindOutb)
	binary.LittleEndian.PutUint32(ob[4:], uint32(len(ob)))
	ob[8] = cmd
	buf = append(buf, ob...)
	num++

	if len(buf) > smiMaxProgramBytes {
		buf = buf[:smiMaxProgramBytes]
	}
	return &bundle{NumCalls: num, Wire: buf}
}

func pokeGuest(data []byte, b *bundle, timeout time.Duration) bool {
	writeU32(data, smiOffMagic, smiMagic)
	writeU32(data, smiOffNcalls, uint32(b.NumCalls))
	copy(data[smiOffCalls:smiOffCalls+uint32(len(b.Wire))], b.Wire)
	writeU32(data, smiOffGuestStatus, 0)
	cur := readU32(data, smiOffHostSeq)
	want := cur + 1
	writeU32(data, smiOffHostSeq, want)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if readU32(data, smiOffGuestSeq) == want {
			return true
		}
		time.Sleep(50 * time.Microsecond)
	}
	return false
}

func waitForGuest(data []byte) error {
	deadline := time.Now().Add(120 * time.Second)
	rng := rand.New(rand.NewSource(0xdeadbeef))
	for time.Now().Before(deadline) {
		// A trivial outb-only bundle as a heartbeat probe.
		b := generateBlindBundle(rng)
		if pokeGuest(data, b, 1*time.Second) {
			return nil
		}
	}
	return fmt.Errorf("guest never acked the heartbeat bundle")
}

func launchQemu(ctx context.Context, varsCopy string) *exec.Cmd {
	args := []string{
		"-machine", "q35,accel=kvm,smm=on",
		"-cpu", "host",
		"-m", "1024",
		"-nodefaults",
		"-no-reboot",
		"-nographic",
		"-serial", "mon:stdio",
		"-global", "driver=cfi.pflash01,property=secure,value=on",
		"-drive", "if=pflash,format=raw,unit=0,readonly=on,file=" + *flagOvmfCode,
		"-drive", "if=pflash,format=raw,unit=1,file=" + varsCopy,
		"-debugcon", "file:" + *flagDebugLog,
		"-global", "isa-debugcon.iobase=0x402",
		"-kernel", *flagKernel,
		"-initrd", *flagInitrd,
		"-append", "console=ttyS0 quiet panic=-1",
		"-object", fmt.Sprintf("memory-backend-file,id=syzsmi,share=on,mem-path=%s,size=256M", *flagShmem),
		"-device", "ivshmem-plain,memdev=syzsmi",
	}
	cmd := exec.CommandContext(ctx, *flagQemu, args...)
	cmd.Stdout = nil
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		fail("start qemu: %v", err)
	}
	return cmd
}

func scanDebugLog(path string) []string {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var titles []string
	patterns := []string{
		"!!!! X64 Exception Type",
		"ASSERT [",
		"==ERROR: AddressSanitizer:",
		"SMM exception",
		"SMI handler crash",
	}
	for _, line := range splitLines(body) {
		for _, p := range patterns {
			if containsBytes(line, []byte(p)) {
				titles = append(titles, string(trimBytes(line)))
				break
			}
		}
	}
	return titles
}

// ---------------- helpers (small mmap + io stubs that mirror syz-edk2-fuzz) ---

func writeU32(b []byte, off uint32, v uint32) {
	binary.LittleEndian.PutUint32(b[off:off+4], v)
}

func readU32(b []byte, off uint32) uint32 {
	return binary.LittleEndian.Uint32(b[off : off+4])
}

func zeroSlice(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func copyFile(src, dst string) error {
	in, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, in, 0o644)
}

func truncateShmem(path string, size int64) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Truncate(size)
}

type mappedFile struct {
	Data []byte
	f    *os.File
}

func (m *mappedFile) Close() error {
	if m.Data != nil {
		_ = syscall.Munmap(m.Data)
	}
	if m.f != nil {
		_ = m.f.Close()
	}
	return nil
}

func mmapFile(path string, size int64) (*mappedFile, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	data, err := syscall.Mmap(int(f.Fd()), 0, int(size),
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &mappedFile{Data: data, f: f}, nil
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}

func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func trimBytes(b []byte) []byte {
	i, j := 0, len(b)
	for i < j && (b[i] == ' ' || b[i] == '\t' || b[i] == '\r') {
		i++
	}
	for j > i && (b[j-1] == ' ' || b[j-1] == '\t' || b[j-1] == '\r') {
		j--
	}
	return b[i:j]
}

func dumpDebugTail(path string, lines int) {
	body, err := os.ReadFile(path)
	if err != nil {
		return
	}
	all := splitLines(body)
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	fmt.Fprintln(os.Stderr, "--- last", lines, "lines of", path, "---")
	for _, l := range all {
		fmt.Fprintln(os.Stderr, string(l))
	}
}

func fail(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
