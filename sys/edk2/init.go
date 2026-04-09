// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package edk2 contains the syzkaller target initialization for the EDK2
// (UEFI/OVMF) fuzzing target. See docs/edk2_design.md.
package edk2

import (
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

func InitTarget(target *prog.Target) {
	target.MakeDataMmap = targets.MakeSyzMmap(target)
}
