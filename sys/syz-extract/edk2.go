// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"path/filepath"
	"strings"

	"github.com/google/syzkaller/pkg/compiler"
)

// edk2 is a syz-extract back-end for the edk2 (UEFI/OVMF) target. It points
// the generic clang-based extractor at the EDK2 source tree's MdePkg headers
// so syzlang `include` directives in sys/edk2/*.txt can pick up real EFI_*
// constants. Today sys/edk2/edk2.txt has `meta noextract` and ships its
// constants in edk2.txt.const directly, so this extractor is a no-op for the
// initial set of files; it exists so subsequent description files can drop
// the noextract attribute and use real header constants.
type edk2 struct{}

func (*edk2) prepare(sourcedir string, build bool, arches []*Arch) error {
	return nil
}

func (*edk2) prepareArch(arch *Arch) error {
	return nil
}

func (*edk2) processFile(arch *Arch, info *compiler.ConstInfo) (
	map[string]uint64, map[string]bool, error) {
	dir := arch.sourceDir
	args := []string{
		"-fmessage-length=0",
		"-nostdinc",
		"-D__EFIAPI__=",
		"-D__attribute__(x)=",
		"-DEFIAPI=",
		"-I", filepath.Join(dir, "MdePkg", "Include"),
		"-I", filepath.Join(dir, "MdePkg", "Include", "X64"),
		"-I", filepath.Join(dir, "MdeModulePkg", "Include"),
		"-I", filepath.Join(dir, "OvmfPkg", "Include"),
	}
	for _, incdir := range info.Incdirs {
		args = append(args, "-I"+filepath.Join(dir, incdir))
	}
	if arch.includeDirs != "" {
		for _, incdir := range strings.Split(arch.includeDirs, ",") {
			args = append(args, "-I"+incdir)
		}
	}
	params := &extractParams{
		DeclarePrintf: true,
		TargetEndian:  arch.target.HostEndian,
	}
	return extract(info, "clang", args, params)
}
