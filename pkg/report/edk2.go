// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"regexp"
)

// edk2 is the report parser for the edk2 (UEFI/OVMF) target. It walks
// the QEMU serial log produced by OVMF and recognises the three families of
// failures the agent can produce:
//
//   - CpuExceptionHandlerLib dumps after a guest CPU exception, of the form
//     "!!!! X64 Exception Type - 0E ..." followed by a register dump.
//   - DebugLib ASSERT()s, of the form "ASSERT [<file>:<line>] <expr>".
//   - SyzAgentDxe-emitted records starting with "[SYZ-AGENT] panic: ".
//   - AsanLib reports of the form "==ERROR: AddressSanitizer: ...".
//
// The implementation deliberately mirrors freebsd.go in style and uses the
// shared simpleLineParser infrastructure; we don't need a custom stack
// extractor for v1.
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

func (ctx *edk2) Parse(output []byte) *Report {
	return simpleLineParser(output, edk2Oopses, edk2StackParams, ctx.ignores)
}

func (ctx *edk2) Symbolize(rep *Report) error {
	return nil
}

var edk2StackParams = &stackParams{}

// Suppressions for benign messages that OVMF prints during normal boot.
var edk2Suppressions = []string{
	"PROGRESS CODE",
	"Loading driver at ",
}

var edk2Oopses = append([]*oops{
	{
		[]byte("!!!! X64 Exception Type"),
		[]oopsFormat{
			{
				title: compile(`!!!! X64 Exception Type - ([0-9A-F]+).*\n` +
					`(?s:.*?)` +
					`!!!! Find image based on [^\n]*?([A-Za-z0-9_]+)\.(?:efi|dll)`),
				fmt: "edk2: X64 exception %[1]v in %[2]v",
			},
			{
				title: compile(`!!!! X64 Exception Type - ([0-9A-F]+).*`),
				fmt:   "edk2: X64 exception %[1]v",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("ASSERT ["),
		[]oopsFormat{
			{
				title: compile(`ASSERT \[(?P<mod>[A-Za-z0-9_]+)\] (?P<src>[^:]+):(\d+) (?P<expr>[^\r\n]+)`),
				fmt:   "edk2: ASSERT in %[1]v (%[2]v:%[3]v): %[4]v",
			},
		},
		[]*regexp.Regexp{},
	},
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
		[]byte("==ERROR: AddressSanitizer"),
		[]oopsFormat{
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
		[]byte("DXE_ASSERT"),
		[]oopsFormat{
			{
				title: compile(`DXE_ASSERT: (.*)`),
				fmt:   "edk2: DXE assert: %[1]v",
			},
		},
		[]*regexp.Regexp{},
	},
}, commonOopses...)
