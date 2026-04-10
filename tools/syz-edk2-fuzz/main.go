// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-edk2-fuzz is a small standalone driver that runs an end-to-end
// fuzzing campaign against an OvmfPkgX64 build with SyzAgentDxe inside.
// It is intentionally NOT plugged into vm/qemu / syz-manager because
// the edk2 target has no SSH/OS the standard syzkaller VM driver can
// reach. Instead this tool:
//
//   - launches QEMU/KVM with OVMF as pflash and an ivshmem-plain
//     device backed by a host file we mmap;
//   - generates random programs in the SyzAgent wire format (the same
//     one executor/common_edk2.h speaks) and pokes them across the
//     shmem doorbell;
//   - measures coverage by counting unique PCs the SyzCoverLib trace
//     runtime writes back into the same shmem region;
//   - records crashes parsed from the OVMF debug log
//     (CpuExceptionHandlerLib, ASSERT, ASAN, [SYZ-AGENT] panic).
//
// After the campaign it writes a JSON summary to stdout.
//
// This tool gives us a real boot-and-fuzz signal on a host that has
// only stock QEMU 6.2 and no kernel-snapshot support. Real
// syzkaller-driven snapshot fuzzing remains the long-term goal; see
// docs/edk2_design.md §3.5 / §6.2.

package main

import (
	"bytes"
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
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// Wire format constants must stay in lockstep with
// executor/common_edk2.h on the host side and
// OvmfPkg/SyzAgentDxe/SyzAgentDxe.h on the firmware side.
const (
	edk2Magic           uint32 = 0x53595A45 // 'SYZE'
	edk2OffMagic        uint32 = 0x0000
	edk2OffNcalls       uint32 = 0x0004
	edk2OffCalls        uint32 = 0x0008
	edk2OffHostSeq      uint32 = 0x1000
	edk2OffGuestSeq     uint32 = 0x1004
	edk2OffGuestStatus  uint32 = 0x1008
	edk2OffCoverCount   uint32 = 0x2000
	edk2OffCoverPcs     uint32 = 0x2004
	edk2MaxCalls               = 32
	edk2MaxProgramBytes        = 0x1000 - 8 // OFF_HOST_SEQ - OFF_CALLS

	// SYZ_EDK2_API_* IDs from SyzAgentDxe.h.
	apiNop                = 1
	apiSetVariable        = 100
	apiGetVariable        = 101
	apiQueryVariableInfo  = 102
	apiAllocatePool       = 200
	apiFreePool           = 201
	apiAllocatePages      = 202
	apiFreePages          = 203
	apiLocateProtocol     = 300
	apiLocateHandleBuffer = 301
	apiHiiNewPackageList  = 400
	apiHiiRemovePkgList   = 401
	apiAsanPoison         = 500
	apiAsanUnpoison       = 501
	apiAsanReport         = 502
)

var (
	flagOvmfCode    = flag.String("ovmf-code", "", "path to OVMF_CODE.fd (required)")
	flagOvmfVars    = flag.String("ovmf-vars", "", "path to OVMF_VARS.fd template (required)")
	flagOvmfDebug   = flag.String("ovmf-debug-log", "", "path to write OVMF debug-con output")
	flagShmem       = flag.String("shmem", "/tmp/syz-edk2.shm", "path to backing file for the ivshmem region")
	flagWorkdir     = flag.String("workdir", "/tmp/syz-edk2-work", "directory for per-VM artifacts")
	flagDuration    = flag.Duration("duration", 30*time.Second, "fuzzing campaign length")
	flagSeed        = flag.Int64("seed", time.Now().UnixNano(), "random seed")
	flagQemu        = flag.String("qemu", "qemu-system-x86_64", "qemu binary")
	flagPokeTimeout = flag.Duration("poke-timeout", 2*time.Second, "per-program ack timeout")
	flagVerbose     = flag.Bool("v", false, "verbose: print every poke")
	flagOnlyNop     = flag.Bool("only-nop", false, "generate only nop programs (debug)")
	flagCallSet     = flag.String("call-set", "all", "comma-separated subset of: nop,mem,var,proto,hii,asan,all")
	flagSnapshot    = flag.Int("snapshot-every", 0, "if >0, cold-restart QEMU every N programs to give the agent a fresh VM (poor-man's snapshot fuzzing)")
	flagUseGrammar  = flag.Bool("use-grammar", false, "use the syzkaller prog package + sys/edk2 syzlang descriptions to generate programs (real grammar) instead of the hand-rolled random emitter")
	flagDumpFirst   = flag.Bool("dump-first", false, "dump the first generated program to stderr (debug)")
	flagGrammarSkip = flag.String("grammar-skip", "", "comma-separated list of API ids to drop from grammar-generated programs (debug)")
)

type stats struct {
	Programs       atomic.Uint64
	Acks           atomic.Uint64
	Timeouts       atomic.Uint64
	GuestErrors    atomic.Uint64
	Calls          atomic.Uint64
	UniqueCovPCs   atomic.Uint64
	BootDurationMs int64
	StartedAt      time.Time
}

type runResult struct {
	Programs        uint64   `json:"programs"`
	Acks            uint64   `json:"acks"`
	Timeouts        uint64   `json:"timeouts"`
	GuestErrors     uint64   `json:"guest_errors"`
	CallsDispatched uint64   `json:"calls_dispatched"`
	UniqueCoverPCs  uint64   `json:"unique_cover_pcs"`
	DurationSec     float64  `json:"duration_sec"`
	BootDurationSec float64  `json:"boot_duration_sec"`
	CrashTitles     []string `json:"crash_titles"`
	OK              bool     `json:"ok"`
}

func main() {
	flag.Parse()
	if *flagOvmfCode == "" || *flagOvmfVars == "" {
		fmt.Fprintln(os.Stderr, "-ovmf-code and -ovmf-vars are required")
		os.Exit(2)
	}
	if err := os.MkdirAll(*flagWorkdir, 0o755); err != nil {
		fail("mkdir workdir: %v", err)
	}
	if *flagOvmfDebug == "" {
		*flagOvmfDebug = filepath.Join(*flagWorkdir, "edk2-debug.log")
	}

	// Per-VM writable copy of OVMF_VARS.fd so SetVariable works.
	varsCopy := filepath.Join(*flagWorkdir, "OVMF_VARS.fd")
	if err := copyFile(*flagOvmfVars, varsCopy); err != nil {
		fail("copy vars: %v", err)
	}

	// Pre-allocate the ivshmem backing file. The first 2 MiB are the
	// SyzAgent control region (program payload + doorbell + cover ring).
	// Everything past offset 0x200000 is reserved for the asan shadow
	// window when ASAN_INSTRUMENT=TRUE OVMF builds late-bind it via
	// gAsanShadowReadyProtocolGuid. 256 MiB total ⇒ 254 MiB shadow ⇒
	// ~2 GiB of trackable physical-memory range at SHADOW_SCALE=3.
	const shmemSize = 256 << 20
	if err := truncateShmem(*flagShmem, shmemSize); err != nil {
		fail("create shmem: %v", err)
	}

	// Mmap the shmem so we can poke and read directly.
	shmem, err := mmapFile(*flagShmem, shmemSize)
	if err != nil {
		fail("mmap shmem: %v", err)
	}
	defer shmem.Close()
	// Zero the doorbell words and the cover ring before launch.
	for i := range shmem.Data[edk2OffHostSeq : edk2OffHostSeq+12] {
		shmem.Data[int(edk2OffHostSeq)+i] = 0
	}
	for i := 0; i < 16; i++ {
		shmem.Data[int(edk2OffCoverCount)+i] = 0
	}

	// Boot QEMU.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startBoot := time.Now()
	qemu := launchQemu(ctx, varsCopy)
	defer func() {
		_ = qemu.Process.Kill()
		_, _ = qemu.Process.Wait()
	}()

	// Wait for SyzAgentDxe to set up the dispatch timer. We poll the
	// agent by sending a sentinel "nop" program; once we get a clean
	// ack with status=0 we know the transport is up.
	if err := waitForAgent(shmem.Data); err != nil {
		dumpDebugTail(*flagOvmfDebug, 80)
		fail("agent not ready: %v", err)
	}
	bootMs := time.Since(startBoot).Milliseconds()

	// Hook ^C so we still report what we did so far.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; cancel() }()

	st := &stats{StartedAt: time.Now()}
	st.BootDurationMs = bootMs
	deadline := time.Now().Add(*flagDuration)
	rng := rand.New(rand.NewSource(*flagSeed))
	pcSet := make(map[uint64]struct{})

	var gt *grammarTarget
	if *flagUseGrammar {
		var gerr error
		gt, gerr = getGrammarTarget()
		if gerr != nil {
			fail("grammar init: %v", gerr)
		}
		fmt.Fprintf(os.Stderr, "[grammar] prog.Target ready: %d syscalls in sys/edk2\n",
			len(gt.target.Syscalls))
		if *flagGrammarSkip != "" {
			grammarSkipIDs = map[uint32]bool{}
			for _, s := range strings.Split(*flagGrammarSkip, ",") {
				if v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32); err == nil {
					grammarSkipIDs[uint32(v)] = true
				}
			}
			fmt.Fprintf(os.Stderr, "[grammar] skipping ids %v\n", grammarSkipIDs)
		}
	}

	progsThisVM := uint64(0)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
		default:
		}
		// Cold-restart for state isolation if -snapshot-every is set.
		if *flagSnapshot > 0 && progsThisVM >= uint64(*flagSnapshot) {
			_ = qemu.Process.Kill()
			_, _ = qemu.Process.Wait()
			// Re-zero the doorbell + cover ring + recopy vars.
			for i := range shmem.Data[edk2OffHostSeq : edk2OffHostSeq+12] {
				shmem.Data[int(edk2OffHostSeq)+i] = 0
			}
			writeU32(shmem.Data, edk2OffCoverCount, 0)
			_ = copyFile(*flagOvmfVars, varsCopy)
			qemu = launchQemu(ctx, varsCopy)
			if err := waitForAgent(shmem.Data); err != nil {
				st.Timeouts.Add(1)
				break
			}
			progsThisVM = 0
		}
		var prog *program
		if gt != nil {
			gp, gerr := gt.generateGrammarProgram(rng)
			if gerr != nil || gp == nil {
				// Fall back to hand-rolled random for this iteration
				// so a single bad sample doesn't kill the campaign.
				prog = generateProgram(rng)
			} else {
				prog = gp
			}
		} else {
			prog = generateProgram(rng)
		}
		if *flagDumpFirst && st.Programs.Load() == 0 {
			fmt.Fprintf(os.Stderr, "[dump] first program ncalls=%d wirelen=%d\n",
				prog.NumCalls, len(prog.Wire))
			off := 0
			for i := 0; i < prog.NumCalls && off+8 <= len(prog.Wire); i++ {
				cid := binary.LittleEndian.Uint32(prog.Wire[off:])
				csz := binary.LittleEndian.Uint32(prog.Wire[off+4:])
				fmt.Fprintf(os.Stderr, "[dump]   call %d: id=%d size=%d\n", i, cid, csz)
				if csz < 8 || off+int(csz) > len(prog.Wire) {
					fmt.Fprintf(os.Stderr, "[dump]   MALFORMED — bailing\n")
					break
				}
				off += int(csz)
			}
		}
		st.Programs.Add(1)
		progsThisVM++
		st.Calls.Add(uint64(prog.NumCalls))
		// Reset cover ring on each iteration so we get a per-program count.
		writeU32(shmem.Data, edk2OffCoverCount, 0)
		ok := pokeAgent(shmem.Data, prog, *flagPokeTimeout)
		if !ok {
			st.Timeouts.Add(1)
			if *flagVerbose || st.Programs.Load() < 5 {
				fmt.Fprintf(os.Stderr,
					"[poke %d] TIMEOUT ncalls=%d wirelen=%d host_seq=%d guest_seq=%d\n",
					st.Programs.Load(), prog.NumCalls, len(prog.Wire),
					readU32(shmem.Data, edk2OffHostSeq),
					readU32(shmem.Data, edk2OffGuestSeq))
			}
			continue
		}
		status := readU32(shmem.Data, edk2OffGuestStatus)
		if status != 0 {
			st.GuestErrors.Add(1)
		} else {
			st.Acks.Add(1)
		}
		drainCoverage(shmem.Data, pcSet)
		if *flagVerbose {
			fmt.Fprintf(os.Stderr, "[poke %d] ncalls=%d status=%d cov=%d\n",
				st.Programs.Load(), prog.NumCalls, status, len(pcSet))
		}
	}
	st.UniqueCovPCs.Store(uint64(len(pcSet)))

	// Stop QEMU and parse crash titles from the debug log.
	cancel()
	_ = qemu.Process.Kill()
	_, _ = qemu.Process.Wait()
	crashes := scanDebugLog(*flagOvmfDebug)

	res := runResult{
		Programs:        st.Programs.Load(),
		Acks:            st.Acks.Load(),
		Timeouts:        st.Timeouts.Load(),
		GuestErrors:     st.GuestErrors.Load(),
		CallsDispatched: st.Calls.Load(),
		UniqueCoverPCs:  st.UniqueCovPCs.Load(),
		DurationSec:     time.Since(st.StartedAt).Seconds(),
		BootDurationSec: float64(st.BootDurationMs) / 1000.0,
		CrashTitles:     crashes,
		OK:              st.Programs.Load() > 0 && st.Acks.Load() > 0,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(&res)
	if !res.OK {
		os.Exit(1)
	}
}

// ---------- program generation ----------

type program struct {
	NumCalls int
	Wire     []byte
}

// generateProgram emits a packed program in the SyzAgent wire format.
// We do all serialization here so we don't need to plumb the prog
// package's exec format into the agent — that work is left for when
// the syzkaller VM driver is wired up.
func generateProgram(rng *rand.Rand) *program {
	n := 1 + rng.Intn(8)
	if n > edk2MaxCalls {
		n = edk2MaxCalls
	}
	var buf bytes.Buffer
	for i := 0; i < n; i++ {
		emitRandomCall(&buf, rng)
		if buf.Len() > edk2MaxProgramBytes-64 {
			n = i + 1
			break
		}
	}
	return &program{NumCalls: n, Wire: buf.Bytes()}
}

// emitRandomCall picks one of the agent's commands at random and
// appends a (call, size, payload) record to buf.
func emitRandomCall(buf *bytes.Buffer, rng *rand.Rand) {
	if *flagOnlyNop {
		emitNop(buf, rng)
		return
	}
	choices := buildCallChoices()
	choices[rng.Intn(len(choices))](buf, rng)
}

func buildCallChoices() []func(*bytes.Buffer, *rand.Rand) {
	sets := map[string][]func(*bytes.Buffer, *rand.Rand){
		"nop":   {emitNop},
		"mem":   {emitAllocPool, emitFreePool, emitAllocPages, emitFreePages},
		"var":   {emitSetVariable, emitGetVariable, emitQueryVarInfo},
		"proto": {emitLocateProtocol, emitLocateHandleBuffer},
		"hii":   {emitHiiNewPackageList, emitHiiRemovePackageList},
		"asan":  {emitAsanPoison, emitAsanUnpoison, emitAsanReport},
	}
	if *flagCallSet == "all" {
		// HII is excluded from "all" because Hii->NewPackageList walks
		// fuzzer-controlled package headers and easily wedges on
		// malformed input. Re-enable explicitly with -call-set=...,hii
		// once the agent constructs a valid outer header from the
		// fuzzer's payload. Tracked in docs/edk2_design.md §6.x.
		var all []func(*bytes.Buffer, *rand.Rand)
		for _, k := range []string{"nop", "mem", "var", "proto", "asan"} {
			all = append(all, sets[k]...)
		}
		return all
	}
	var out []func(*bytes.Buffer, *rand.Rand)
	for _, name := range bytes.Split([]byte(*flagCallSet), []byte(",")) {
		if v, ok := sets[string(bytes.TrimSpace(name))]; ok {
			out = append(out, v...)
		}
	}
	if len(out) == 0 {
		out = sets["nop"]
	}
	return out
}

func writeHdr(buf *bytes.Buffer, call uint32, payloadLen int) {
	var hdr [8]byte
	binary.LittleEndian.PutUint32(hdr[0:4], call)
	binary.LittleEndian.PutUint32(hdr[4:8], uint32(8+payloadLen))
	buf.Write(hdr[:])
}

func emitNop(buf *bytes.Buffer, rng *rand.Rand) {
	writeHdr(buf, apiNop, 8)
	var p [8]byte
	binary.LittleEndian.PutUint64(p[:], rng.Uint64())
	buf.Write(p[:])
}

func emitAllocPool(buf *bytes.Buffer, rng *rand.Rand) {
	writeHdr(buf, apiAllocatePool, 8)
	var p [8]byte
	binary.LittleEndian.PutUint32(p[0:4], uint32(rng.Intn(15)))      // mem type
	binary.LittleEndian.PutUint32(p[4:8], uint32(1+rng.Intn(65536))) // size
	buf.Write(p[:])
}

func emitFreePool(buf *bytes.Buffer, rng *rand.Rand) {
	writeHdr(buf, apiFreePool, 4)
	var p [4]byte
	binary.LittleEndian.PutUint32(p[:], uint32(rng.Intn(32)))
	buf.Write(p[:])
}

func emitAllocPages(buf *bytes.Buffer, rng *rand.Rand) {
	writeHdr(buf, apiAllocatePages, 12)
	var p [12]byte
	binary.LittleEndian.PutUint32(p[0:4], uint32(rng.Intn(3)))    // alloc type
	binary.LittleEndian.PutUint32(p[4:8], uint32(rng.Intn(15)))   // mem type
	binary.LittleEndian.PutUint32(p[8:12], uint32(1+rng.Intn(8))) // pages
	buf.Write(p[:])
}

func emitFreePages(buf *bytes.Buffer, rng *rand.Rand) {
	writeHdr(buf, apiFreePages, 4)
	var p [4]byte
	binary.LittleEndian.PutUint32(p[:], uint32(rng.Intn(32)))
	buf.Write(p[:])
}

func emitSetVariable(buf *bytes.Buffer, rng *rand.Rand) {
	nameRunes := 4 + rng.Intn(8)
	dataLen := rng.Intn(64)
	payloadLen := 8 + nameRunes*2 + dataLen
	writeHdr(buf, apiSetVariable, payloadLen)
	// header: NameSize(2) Attributes(4) DataSize(2)
	binary.Write(buf, binary.LittleEndian, uint16(nameRunes*2))
	binary.Write(buf, binary.LittleEndian, uint32(rng.Uint32()&0x67))
	binary.Write(buf, binary.LittleEndian, uint16(dataLen))
	for i := 0; i < nameRunes; i++ {
		binary.Write(buf, binary.LittleEndian, uint16('A'+rng.Intn(26)))
	}
	for i := 0; i < dataLen; i++ {
		buf.WriteByte(byte(rng.Intn(256)))
	}
}

func emitGetVariable(buf *bytes.Buffer, rng *rand.Rand) {
	nameRunes := 4 + rng.Intn(8)
	payloadLen := 4 + nameRunes*2
	writeHdr(buf, apiGetVariable, payloadLen)
	binary.Write(buf, binary.LittleEndian, uint16(nameRunes*2))
	binary.Write(buf, binary.LittleEndian, uint16(256))
	for i := 0; i < nameRunes; i++ {
		binary.Write(buf, binary.LittleEndian, uint16('A'+rng.Intn(26)))
	}
}

func emitQueryVarInfo(buf *bytes.Buffer, rng *rand.Rand) {
	writeHdr(buf, apiQueryVariableInfo, 4)
	binary.Write(buf, binary.LittleEndian, uint32(rng.Uint32()&0x67))
}

func emitLocateProtocol(buf *bytes.Buffer, rng *rand.Rand) {
	writeHdr(buf, apiLocateProtocol, 4)
	// SyzEdk2Proto* IDs are 100..107, 200..202.
	ids := []uint32{100, 101, 102, 103, 104, 105, 106, 107, 200, 201, 202}
	binary.Write(buf, binary.LittleEndian, ids[rng.Intn(len(ids))])
}

func emitLocateHandleBuffer(buf *bytes.Buffer, rng *rand.Rand) {
	writeHdr(buf, apiLocateHandleBuffer, 8)
	binary.Write(buf, binary.LittleEndian, uint32(rng.Intn(3)))
	ids := []uint32{100, 101, 102, 103, 104, 105, 106, 107, 200, 201, 202}
	binary.Write(buf, binary.LittleEndian, ids[rng.Intn(len(ids))])
}

func emitHiiNewPackageList(buf *bytes.Buffer, rng *rand.Rand) {
	dataLen := 8 + rng.Intn(64)
	payloadLen := 2 + dataLen
	writeHdr(buf, apiHiiNewPackageList, payloadLen)
	binary.Write(buf, binary.LittleEndian, uint16(dataLen))
	for i := 0; i < dataLen; i++ {
		buf.WriteByte(byte(rng.Intn(256)))
	}
}

func emitHiiRemovePackageList(buf *bytes.Buffer, rng *rand.Rand) {
	writeHdr(buf, apiHiiRemovePkgList, 4)
	binary.Write(buf, binary.LittleEndian, uint32(rng.Intn(16)))
}

func emitAsanPoison(buf *bytes.Buffer, rng *rand.Rand) {
	emitAsanCommon(buf, apiAsanPoison, rng)
}
func emitAsanUnpoison(buf *bytes.Buffer, rng *rand.Rand) {
	emitAsanCommon(buf, apiAsanUnpoison, rng)
}
func emitAsanReport(buf *bytes.Buffer, rng *rand.Rand) {
	emitAsanCommon(buf, apiAsanReport, rng)
}
func emitAsanCommon(buf *bytes.Buffer, id uint32, rng *rand.Rand) {
	writeHdr(buf, id, 16)
	binary.Write(buf, binary.LittleEndian, uint32(rng.Intn(32))) // alloc index
	binary.Write(buf, binary.LittleEndian, uint32(rng.Intn(64))) // offset
	binary.Write(buf, binary.LittleEndian, uint32(1+rng.Intn(8)))
	buf.WriteByte(byte(rng.Intn(2))) // is_write
	buf.WriteByte(0)
	buf.WriteByte(0)
	buf.WriteByte(0)
}

// ---------- transport ----------

func pokeAgent(data []byte, prog *program, timeout time.Duration) bool {
	// Write magic + ncalls + payload.
	writeU32(data, edk2OffMagic, edk2Magic)
	writeU32(data, edk2OffNcalls, uint32(prog.NumCalls))
	copy(data[edk2OffCalls:edk2OffCalls+uint32(len(prog.Wire))], prog.Wire)
	// Doorbell.
	writeU32(data, edk2OffGuestStatus, 0)
	cur := readU32(data, edk2OffHostSeq)
	want := cur + 1
	writeU32(data, edk2OffHostSeq, want)
	// Wait for ack.
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if readU32(data, edk2OffGuestSeq) == want {
			return true
		}
		time.Sleep(50 * time.Microsecond)
	}
	return false
}

// waitForAgent boots the agent in by sending a single nop and
// retrying every 500 ms until we get an ack (status doesn't matter
// here, we only care that the dispatcher is alive). The 60 s
// deadline accommodates ASAN+coverage-instrumented builds, which can
// take ~30 s to boot all the way into BDS on a busy host.
func waitForAgent(data []byte) error {
	deadline := time.Now().Add(90 * time.Second)
	rng := rand.New(rand.NewSource(0xa9e21))
	for time.Now().Before(deadline) {
		var buf bytes.Buffer
		emitNop(&buf, rng)
		prog := &program{NumCalls: 1, Wire: buf.Bytes()}
		if pokeAgent(data, prog, 500*time.Millisecond) {
			return nil
		}
	}
	return fmt.Errorf("agent never acked the sentinel poke")
}

func drainCoverage(data []byte, set map[uint64]struct{}) {
	count := readU32(data, edk2OffCoverCount)
	if count == 0 {
		return
	}
	if count > 0x10000 {
		count = 0x10000
	}
	for i := uint32(0); i < count; i++ {
		off := edk2OffCoverPcs + i*8
		pc := binary.LittleEndian.Uint64(data[off : off+8])
		if pc != 0 {
			set[pc] = struct{}{}
		}
	}
}

// ---------- QEMU launch ----------

func launchQemu(ctx context.Context, varsCopy string) *exec.Cmd {
	args := []string{
		"-machine", "q35,accel=kvm",
		"-cpu", "host",
		"-m", "1024",
		"-nodefaults",
		"-no-reboot",
		"-nographic",
		"-serial", "null",
		"-drive", "if=pflash,format=raw,readonly=on,file=" + *flagOvmfCode,
		"-drive", "if=pflash,format=raw,file=" + varsCopy,
		"-debugcon", "file:" + *flagOvmfDebug,
		"-global", "isa-debugcon.iobase=0x402",
		"-object", fmt.Sprintf("memory-backend-file,id=syzcov,share=on,mem-path=%s,size=256M", *flagShmem),
		"-device", "ivshmem-plain,memdev=syzcov",
	}
	cmd := exec.CommandContext(ctx, *flagQemu, args...)
	cmd.Stdout = nil
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		fail("start qemu: %v", err)
	}
	return cmd
}

// ---------- crash log scanning ----------

func scanDebugLog(path string) []string {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var titles []string
	patterns := []string{
		"!!!! X64 Exception Type",
		"ASSERT [",
		"[SYZ-AGENT] panic:",
		"==ERROR: AddressSanitizer:",
	}
	for _, line := range bytes.Split(body, []byte("\n")) {
		for _, p := range patterns {
			if bytes.Contains(line, []byte(p)) {
				titles = append(titles, string(bytes.TrimSpace(line)))
				break
			}
		}
	}
	return titles
}

func dumpDebugTail(path string, lines int) {
	body, err := os.ReadFile(path)
	if err != nil {
		return
	}
	all := bytes.Split(body, []byte("\n"))
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	fmt.Fprintln(os.Stderr, "--- last", lines, "lines of", path, "---")
	for _, l := range all {
		fmt.Fprintln(os.Stderr, string(l))
	}
}

// ---------- helpers ----------

func writeU32(b []byte, off uint32, v uint32) {
	binary.LittleEndian.PutUint32(b[off:off+4], v)
}

func readU32(b []byte, off uint32) uint32 {
	return binary.LittleEndian.Uint32(b[off : off+4])
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

func mmapFile(path string, size int) (*mappedFile, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	data, err := syscall.Mmap(int(f.Fd()), 0, size,
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		f.Close()
		return nil, err
	}
	return &mappedFile{Data: data, f: f}, nil
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
