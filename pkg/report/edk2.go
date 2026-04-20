// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// edk2 is the report parser for the edk2 (UEFI/OVMF) target. It walks
// the QEMU serial log produced by OVMF and recognises the families of
// failures the agent can produce:
//
//   - CpuExceptionHandlerLib dumps after a guest CPU exception, of the form
//     "!!!! X64 Exception Type - 0E ..." followed by a register dump.
//   - DebugLib ASSERT()s, of the form "ASSERT [<file>:<line>] <expr>".
//   - SyzAgentDxe-emitted records starting with "[SYZ-AGENT] panic: ".
//   - AsanLib reports of the form "==ERROR: AddressSanitizer: ...".
//   - CpuDeadLoop / DeadLoop infinite loops (firmware halted state).
//   - "lost connection to test machine" wraps when QEMU is killed; we
//     look back through the log to find the last actual error.
type edk2 struct {
	*config
}

func ctorEdk2(cfg *config) (reporterImpl, []string, error) {
	ctx := &edk2{config: cfg}
	return ctx, edk2Suppressions, nil
}

func (ctx *edk2) ContainsCrash(output []byte) bool {
	return containsCrash(output, edk2Oopses, ctx.ignores)
}

// Parse looks for crashes in the QEMU debug log.
func (ctx *edk2) Parse(output []byte) *Report {
	return simpleLineParser(output, edk2Oopses, edk2StackParams, ctx.ignores)
}

// Symbolize walks the report output for "at pc 0xXXX" lines, maps each
// PC to the DXE module it lives in (by parsing the preceding "Loading
// driver at 0xYYY EntryPoint=0xZZZ Name.efi" records), runs addr2line
// on the module's .debug file, and appends the resolved function +
// source location to the report body.
//
// Without this, ASan crash reports look like:
//   ==ERROR: AddressSanitizer: stack-buffer-overflow at pc 0x3FD0679A
// After:
//   ==ERROR: AddressSanitizer: stack-buffer-overflow at pc 0x3FD0679A
//     in DxeCore+0x2979A => CoreGetNextLocateByProtocol at Locate.c:399
func (ctx *edk2) Symbolize(rep *Report) error {
	if ctx.kernelDirs.Obj == "" {
		return nil
	}
	output := rep.Output
	modules := edk2ParseLoadedModules(output)
	if len(modules) == 0 {
		// rep.Output is truncated to a window around the crash by the
		// syzkaller RPC layer — for our use case this usually strips
		// the "Loading driver at 0x..." records that live near the
		// top of the debug log. Fall back to the fwsnap-discover.log
		// file that the vm/qemu layer writes at snapshot-creation
		// time; it has the full boot trace with every module load.
		modules = edk2LoadModulesFromDiscoverLog()
		if len(modules) == 0 {
			return nil
		}
	}

	//
	// Prepend a structured CRASH SUMMARY block before the raw report.
	// The web UI shows the first N chars of rep.Report prominently,
	// so putting the most-actionable info there means triagers don't
	// need to scroll through debugcon noise to find module/file/line.
	//
	var summary []byte
	primaryPC := ""
	primaryKind := ""
	if m := regexp.MustCompile(`==ERROR: AddressSanitizer: ([a-zA-Z0-9_-]+) on address (0x[0-9a-fA-F]+) at pc (0x[0-9a-fA-F]+)`).FindSubmatch(rep.Output); m != nil {
		primaryKind = string(m[1])
		primaryPC = string(m[3])
		summary = append(summary, []byte(fmt.Sprintf(
			"CRASH SUMMARY: ASan %s\n  Fault address: %s\n  Faulting PC:   %s\n",
			primaryKind, m[2], primaryPC))...)
	} else if m := regexp.MustCompile(`X64 Exception Type - ([0-9A-F]+)\([^)]+\)[^\n]*\n(?s:.*?)RIP  - (0x[0-9a-fA-F]+|[0-9A-F]+)`).FindSubmatch(rep.Output); m != nil {
		primaryPC = string(m[2])
		if !strings.HasPrefix(primaryPC, "0x") {
			primaryPC = "0x" + primaryPC
		}
		primaryKind = "X64-exception-" + string(m[1])
		summary = append(summary, []byte(fmt.Sprintf(
			"CRASH SUMMARY: %s\n  Faulting PC: %s\n",
			primaryKind, primaryPC))...)
	} else if m := regexp.MustCompile(`ASSERT \[([A-Za-z0-9_]+)\] ([^:\r\n]+):(\d+)`).FindSubmatch(rep.Output); m != nil {
		summary = append(summary, []byte(fmt.Sprintf(
			"CRASH SUMMARY: DebugLib ASSERT\n  Module: %s\n  Source: %s:%s\n",
			string(m[1]), string(m[2]), string(m[3])))...)
	}

	// Symbolize the primary PC for the title + summary.
	if primaryPC != "" {
		pc, err := strconv.ParseUint(strings.TrimPrefix(primaryPC, "0x"), 16, 64)
		if err == nil {
			if mod := edk2FindModule(modules, pc); mod != nil {
				offset := pc - mod.Base
				summary = append(summary, []byte(fmt.Sprintf(
					"  Module: %s.efi (base=0x%x +0x%x)\n",
					mod.Name, mod.Base, offset))...)
				if debugPath := edk2FindDebugFile(ctx.kernelDirs.Obj, mod.Name); debugPath != "" {
					if info := edk2Addr2Line(debugPath, offset); info != "" {
						summary = append(summary, []byte(fmt.Sprintf(
							"  Function: %s\n", info))...)
						// Promote function+line into the crash title so the
						// web UI main listing shows "edk2: ASan: heap-oob in
						// CoreAllocatePool at Pool.c:266" instead of just
						// "edk2: ASan: heap-buffer-overflow at ADDR...".
						rep.Title = fmt.Sprintf("edk2: %s in %s (%s)",
							primaryKind, mod.Name, info)
						// GuiltyFile lets syzkaller's dashboard bucketize
						// by the offending source file.
						if parts := regexp.MustCompile(` at (.+):(\d+)$`).FindStringSubmatch(info); len(parts) == 3 {
							rep.GuiltyFile = parts[1]
						}
					}
				}
			}
		}
	}

	// Extract the triggering syscall for the summary.
	if m := regexp.MustCompile(`syz_edk2_run_program\$([a-z0-9_]+)\(`).FindSubmatch(rep.Output); m != nil {
		summary = append(summary, []byte(fmt.Sprintf(
			"  Trigger: syz_edk2_run_program$%s\n", string(m[1])))...)
	}

	if len(summary) > 0 {
		summary = append(summary, []byte("\n")...)
	}

	// Find every "at pc 0xXXX" occurrence in the report body and
	// symbolize each.
	var symbolized []byte
	symbolized = append(symbolized, summary...)
	symbolized = append(symbolized, rep.Report...)
	seen := make(map[string]bool)

	//
	// If the crash is an X64 exception, also symbolize every general
	// register whose value lands inside a loaded module. A #GP at
	// unmapped RIP often leaves the CALLER's address in one of the
	// saved registers (RBX, R10, R12, R13, R14), and those are what
	// actually identify the guilty driver.
	//
	regRe := regexp.MustCompile(`R(?:AX|BX|CX|DX|SI|DI|BP|SP|8|9|10|11|12|13|14|15|IP)\s*-\s*(0x[0-9A-Fa-f]+)`)
	for _, m := range regRe.FindAllSubmatch(rep.Output, -1) {
		pcStr := string(m[1])
		if seen[pcStr] {
			continue
		}
		seen[pcStr] = true
		pc, err := strconv.ParseUint(strings.TrimPrefix(pcStr, "0x"), 16, 64)
		if err != nil || pc < 0x100000 {
			continue
		}
		mod := edk2FindModule(modules, pc)
		if mod == nil {
			continue
		}
		offset := pc - mod.Base
		debugPath := edk2FindDebugFile(ctx.kernelDirs.Obj, mod.Name)
		if debugPath == "" {
			continue
		}
		info := edk2Addr2Line(debugPath, offset)
		if info == "" {
			continue
		}
		symbolized = append(symbolized,
			[]byte(fmt.Sprintf("  reg %s => in %s+0x%x => %s\n", pcStr, mod.Name, offset, info))...)
	}

	for _, match := range edk2PcPattern.FindAllSubmatch(rep.Report, -1) {
		pcStr := string(match[1])
		if seen[pcStr] {
			continue
		}
		seen[pcStr] = true
		pc, err := strconv.ParseUint(strings.TrimPrefix(pcStr, "0x"), 16, 64)
		if err != nil {
			continue
		}
		mod := edk2FindModule(modules, pc)
		if mod == nil {
			continue
		}
		offset := pc - mod.Base
		debugPath := edk2FindDebugFile(ctx.kernelDirs.Obj, mod.Name)
		if debugPath == "" {
			continue
		}
		info := edk2Addr2Line(debugPath, offset)
		if info == "" {
			continue
		}
		symbolized = append(symbolized,
			[]byte(fmt.Sprintf("  in %s+0x%x => %s\n", mod.Name, offset, info))...)
	}
	//
	// Append the "last executing test programs" block (if present).
	// This is normally saved to log0 separately but pulling it into
	// the symbolized report makes triage a single-file operation.
	//
	if m := edk2LastProgramsRe.FindSubmatch(rep.Output); m != nil {
		symbolized = append(symbolized, []byte("\n\n")...)
		symbolized = append(symbolized, m[0]...)
	}
	rep.Report = symbolized
	return nil
}

// edk2LoadedModule is a DXE driver loaded at a specific base address.
type edk2LoadedModule struct {
	Base uint64
	Size uint64
	Name string
}

var (
	// Matches both "Loading driver at 0x..." (DXE drivers) and
	// "Loading PEIM at 0x..." (DxeCore.efi itself — loaded by DxeIpl
	// from PEI, where the bugs we find mostly live).
	edk2LoadedModuleRe = regexp.MustCompile(
		`Loading (?:driver|PEIM) at 0x([0-9A-Fa-f]+) EntryPoint=0x[0-9A-Fa-f]+ (\S+)\.efi`)
	edk2ProtectImageRe = regexp.MustCompile(
		`ProtectUefiImageCommon - 0x[0-9A-Fa-f]+\s*\n` +
			`\s*- 0x([0-9A-Fa-f]+) - 0x([0-9A-Fa-f]+)`)
	//
	// Matches both ASan/UBSan "at pc 0x..." and the CpuExceptionHandlerLib
	// register dump lines ("RIP - 0x...", "RSP - 0x..."). Any PC the host
	// can place inside a loaded module gets addr2line'd and appended to
	// the report. For the common "#GP at RIP=low-memory" case this lets
	// us symbolize the CALLER by scanning RSP+N values in the dump.
	//
	edk2PcPattern = regexp.MustCompile(
		`(?:at pc |RIP  - |RIP - |R10  - |R10 - )(0x[0-9A-Fa-f]+)`)
	//
	// "last executing test programs" — syzkaller's VM output includes
	// a history of recently-executed fuzz programs above the crash
	// site. Copy this verbatim into the report so triage doesn't need
	// to cross-reference log0 → report0 manually.
	//
	edk2LastProgramsRe = regexp.MustCompile(
		`(?s)last executing test programs:.*?(?:\n\nkernel console output|$)`)
)

// edk2ParseLoadedModules scans the QEMU debug log for module load
// records. We rely on the "Loading driver at 0x... Name.efi" line for
// base+name and the subsequent "ProtectUefiImageCommon" block for size.
// When the size isn't matched we fall back to a permissive 2 MB window.
func edk2ParseLoadedModules(output []byte) []edk2LoadedModule {
	var mods []edk2LoadedModule
	for _, m := range edk2LoadedModuleRe.FindAllSubmatch(output, -1) {
		base, err := strconv.ParseUint(string(m[1]), 16, 64)
		if err != nil {
			continue
		}
		mods = append(mods, edk2LoadedModule{
			Base: base,
			Size: 0x200000,
			Name: string(m[2]),
		})
	}
	// Narrow the Size field where possible by correlating with the
	// ProtectUefiImageCommon block that follows each load.
	for _, m := range edk2ProtectImageRe.FindAllSubmatch(output, -1) {
		base, _ := strconv.ParseUint(string(m[1]), 16, 64)
		size, _ := strconv.ParseUint(string(m[2]), 16, 64)
		for i := range mods {
			if mods[i].Base == base {
				mods[i].Size = size
			}
		}
	}
	return mods
}

// edk2LoadModulesFromDiscoverLog finds the fwsnap-discover.log file
// (written by vm/qemu/fwsnap_edk2.go during snapshot discovery) and
// parses its module load records. We glob for it under common
// workdir locations relative to the manager's cwd because the
// reporter context doesn't have direct access to cfg.Workdir.
//
// Cached so we only walk the filesystem once per process lifetime.
var edk2DiscoverModulesCache []edk2LoadedModule
var edk2DiscoverModulesCached bool

func edk2LoadModulesFromDiscoverLog() []edk2LoadedModule {
	if edk2DiscoverModulesCached {
		return edk2DiscoverModulesCache
	}
	edk2DiscoverModulesCached = true
	cwd, err := os.Getwd()
	if err != nil {
		return nil
	}
	patterns := []string{
		filepath.Join(cwd, "workdir*", "instance-*", "template", "fwsnap-discover.log"),
		filepath.Join(cwd, "*", "instance-*", "template", "fwsnap-discover.log"),
	}
	var best string
	var bestMtime int64
	for _, pat := range patterns {
		matches, _ := filepath.Glob(pat)
		for _, m := range matches {
			st, err := os.Stat(m)
			if err != nil {
				continue
			}
			if mt := st.ModTime().Unix(); mt > bestMtime {
				bestMtime = mt
				best = m
			}
		}
	}
	if best == "" {
		return nil
	}
	data, err := os.ReadFile(best)
	if err != nil {
		return nil
	}
	edk2DiscoverModulesCache = edk2ParseLoadedModules(data)
	return edk2DiscoverModulesCache
}

func edk2FindModule(mods []edk2LoadedModule, pc uint64) *edk2LoadedModule {
	var best *edk2LoadedModule
	for i := range mods {
		m := &mods[i]
		if pc >= m.Base && pc < m.Base+m.Size {
			if best == nil || m.Base > best.Base {
				best = m
			}
		}
	}
	return best
}

// edk2FindDebugFile walks the Build directory looking for a
// <Name>.debug file. Result is cached per-module to avoid repeated
// walks.
var edk2DebugPathCache = map[string]string{}

func edk2FindDebugFile(kernelObj, name string) string {
	if v, ok := edk2DebugPathCache[name]; ok {
		return v
	}
	// Typical path: Build/OvmfX64/NOOPT_GCC5/X64/<Pkg>/<...>/<Name>/DEBUG/<Name>.debug
	matches, err := filepath.Glob(
		filepath.Join(kernelObj, "**", "*", name+".debug"))
	if err != nil || len(matches) == 0 {
		// Glob doesn't recurse with **; try a manual walk via find.
		cmd := exec.Command("find", kernelObj, "-name", name+".debug", "-print", "-quit")
		out, err := cmd.Output()
		if err != nil || len(out) == 0 {
			edk2DebugPathCache[name] = ""
			return ""
		}
		path := strings.TrimSpace(string(out))
		edk2DebugPathCache[name] = path
		return path
	}
	edk2DebugPathCache[name] = matches[0]
	return matches[0]
}

// edk2Addr2Line invokes addr2line on the module's .debug file at the
// given offset (PC - module_base). Returns "function at file:line" or
// "" on failure.
func edk2Addr2Line(debugPath string, offset uint64) string {
	cmd := exec.Command("addr2line", "-e", debugPath, "-f", "-C",
		fmt.Sprintf("0x%x", offset))
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	lines := bytes.Split(bytes.TrimSpace(out), []byte("\n"))
	if len(lines) < 2 {
		return ""
	}
	fn := strings.TrimSpace(string(lines[0]))
	loc := strings.TrimSpace(string(lines[1]))
	if fn == "??" || loc == "??:?" || loc == "??:0" {
		return ""
	}
	return fmt.Sprintf("%s at %s", fn, loc)
}

var edk2StackParams = &stackParams{
	// Frames to ignore from EDK2 stack traces (the runtime parts).
	frameRes: []*regexp.Regexp{
		regexp.MustCompile(`^DxeMain\b`),
		regexp.MustCompile(`^_ModuleEntryPoint\b`),
		regexp.MustCompile(`^ProcessLibraryConstructorList\b`),
	},
}

// Suppressions for benign messages that OVMF prints during normal boot.
var edk2Suppressions = []string{
	"PROGRESS CODE",
	"Loading driver at ",
}

var edk2Oopses = append([]*oops{
	// [SYZ-AGENT] panic is specifically FIRST so it takes priority over
	// the generic commonOopses "panic:" matcher.
	{
		[]byte("[SYZ-AGENT] panic:"),
		[]oopsFormat{
			{
				title: compile(`\[SYZ-AGENT\] panic: ([^\r\n]+)`),
				fmt:   "edk2: SyzAgent panic: %[1]v",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("!!!! X64 Exception Type"),
		[]oopsFormat{
			// Best: full exception with module name from "Find image based on".
			// %[1] is the hex code (e.g. 0E), %[2] is the module.
			{
				title: compile(`!!!! X64 Exception Type - ([0-9A-F]+)[^\n]*\n` +
					`(?s:.*?)` +
					`!!!! Find image based on [^\n]*?([A-Za-z0-9_]+)\.(?:efi|dll)`),
				fmt: "edk2: X64 exception %[1]v in %[2]v",
			},
			// Generic fallback with hex code when no module name is present.
			{
				title: compile(`!!!! X64 Exception Type - ([0-9A-F]+)[^\n]*`),
				fmt:   "edk2: X64 exception %[1]v",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("ASSERT ["),
		[]oopsFormat{
			// Full form: module + file:line + expression (full path preserved)
			{
				title: compile(`ASSERT \[(?P<mod>[A-Za-z0-9_]+)\] ` +
					`(?P<path>[^:\r\n]+):(?P<line>\d+)[: ] ?(?P<expr>[^\r\n]+)`),
				fmt: "edk2: ASSERT in %[1]v (%[2]v:%[3]v): %[4]v",
			},
			// Without file:line
			{
				title: compile(`ASSERT \[(?P<mod>[A-Za-z0-9_]+)\] [^\r\n]+`),
				fmt:   "edk2: ASSERT in %[1]v",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("ASSERT_EFI_ERROR"),
		[]oopsFormat{
			{
				title: compile(`ASSERT_EFI_ERROR \(Status = ([^)]+)\)`),
				fmt:   "edk2: ASSERT_EFI_ERROR Status=%[1]v",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("==ERROR: AddressSanitizer"),
		[]oopsFormat{
			//
			// Title with PC suffix lets the manager Ignores list
			// suppress specific known bugs by PC without losing the
			// ability to detect new bugs of the same class.
			//
			{
				title: compile(`==ERROR: AddressSanitizer: ([a-zA-Z0-9_-]+) on address 0x[0-9a-fA-F]+ at pc (0x[0-9a-fA-F]+)`),
				fmt:   "edk2: ASan: %[1]v at %[2]v",
			},
			{
				title: compile(`==ERROR: AddressSanitizer: ([a-zA-Z0-9_-]+) on address {{ADDR}}`),
				fmt:   "edk2: ASan: %[1]v",
			},
			{
				title: compile(`==ERROR: AddressSanitizer: ([a-zA-Z0-9_-]+)`),
				fmt:   "edk2: ASan: %[1]v",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		// CpuDeadLoop is what EDK2 calls when something goes wrong and
		// it can't recover. Often follows an ASSERT or unexpected state.
		[]byte("CpuDeadLoop"),
		[]oopsFormat{
			{
				title: compile(`CpuDeadLoop[^\r\n]*`),
				fmt:   "edk2: CpuDeadLoop (firmware halted)",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		// DEADLOOP() macro from BdsLib and other places.
		[]byte("DEAD LOOP"),
		[]oopsFormat{
			{
				title: compile(`DEAD LOOP[^\r\n]*`),
				fmt:   "edk2: DEAD LOOP",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("DXE_ASSERT"),
		[]oopsFormat{
			{
				title: compile(`DXE_ASSERT: ([^\r\n]+)`),
				fmt:   "edk2: DXE assert: %[1]v",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		// Stack overflow detection (canary check)
		[]byte("__stack_chk_fail"),
		[]oopsFormat{
			{
				title: compile(`__stack_chk_fail[^\r\n]*`),
				fmt:   "edk2: stack canary smashed",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		// UBSan reports — use "[UBSan]" prefix to disambiguate from
		// Go runtime panics that also start with "runtime error:".
		[]byte("[UBSan] runtime error:"),
		[]oopsFormat{
			{
				title: compile(`\[UBSan\] runtime error: ([^\r\n]+)`),
				fmt:   "edk2: UBSAN: %[1]v",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		// AsanLib's UBSan handlers print "ASAN MEMORY ACCESS check fail!
		// __ubsan_handle_<type> is called:" to the serial port. Match
		// these so UBSan-detected bugs surface as crash reports.
		[]byte("__ubsan_handle_"),
		[]oopsFormat{
			{
				title: compile(`(__ubsan_handle_[a-z_]+) is called`),
				fmt:   "edk2: UBSAN: %[1]v",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		// AsanLib's generic "ASAN MEMORY ACCESS check fail!" prefix
		// appears before both ASan and UBSan reports. Catch any that
		// weren't matched by the more specific patterns above.
		[]byte("ASAN MEMORY ACCESS check fail"),
		[]oopsFormat{
			{
				title: compile(`ASAN MEMORY ACCESS check fail[^\r\n]*`),
				fmt:   "edk2: ASan: memory access check fail",
			},
		},
		[]*regexp.Regexp{},
	},
}, commonOopses...)
