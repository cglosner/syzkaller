// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
)

// edk2 builds the OVMF firmware image from an EDK2 source checkout that
// already contains the SyzAgentDxe driver and SyzCoverLib library on top of
// upstream OvmfPkg. The expected build flag (set in OvmfPkgX64.dsc) is
// SYZ_AGENT_ENABLE; the resulting OVMF_CODE.fd / OVMF_VARS.fd are copied
// into params.OutputDir together with a freshly-rolled vars template, and
// OVMF.fd is exposed as the syzkaller "kernel object" so the existing
// pkg/symbolizer / pkg/cover paths can pick it up. See docs/edk2_design.md.
//
// Build mode and toolchain default to NOOPT_GCC5SYZ but can be overridden
// via SYZ_EDK2_BUILD_MODE / SYZ_EDK2_TOOLCHAIN.
type edk2 struct{}

func (ctx edk2) build(params Params) (ImageDetails, error) {
	if params.KernelDir == "" {
		return ImageDetails{}, fmt.Errorf("edk2 build: KernelDir is required (path to EDK2 source tree)")
	}
	if _, err := os.Stat(filepath.Join(params.KernelDir, "OvmfPkg", "OvmfPkgX64.dsc")); err != nil {
		return ImageDetails{}, fmt.Errorf("edk2 build: %v does not look like an EDK2 checkout: %w",
			params.KernelDir, err)
	}

	buildMode := os.Getenv("SYZ_EDK2_BUILD_MODE")
	if buildMode == "" {
		buildMode = "NOOPT"
	}
	toolchain := os.Getenv("SYZ_EDK2_TOOLCHAIN")
	if toolchain == "" {
		toolchain = "GCC5SYZ"
	}

	// Bootstrap BaseTools (cheap, idempotent).
	if _, err := ctx.runShell(params, 10*time.Minute,
		"make -C BaseTools -j%d", params.BuildCPUs); err != nil {
		return ImageDetails{}, fmt.Errorf("edk2 build: BaseTools failed: %w", err)
	}

	// edksetup.sh exports a pile of vars; we source it inside the same shell
	// invocation so the build command sees them.
	buildCmd := fmt.Sprintf(
		". ./edksetup.sh && build -p OvmfPkg/OvmfPkgX64.dsc -a X64 -t %s -b %s "+
			"-D SYZ_AGENT_ENABLE=TRUE -D ASAN_ENABLE=TRUE -n %d",
		toolchain, buildMode, params.BuildCPUs)
	if _, err := ctx.runShell(params, 60*time.Minute, buildCmd); err != nil {
		return ImageDetails{}, fmt.Errorf("edk2 build: OvmfPkgX64 failed: %w", err)
	}

	// Locate the build output. EDK2 places it under
	// Build/OvmfX64/<MODE>_<TOOLCHAIN>/FV/.
	fvDir := filepath.Join(params.KernelDir, "Build", "OvmfX64",
		fmt.Sprintf("%s_%s", buildMode, toolchain), "FV")
	for _, name := range []string{"OVMF.fd", "OVMF_CODE.fd", "OVMF_VARS.fd"} {
		src := filepath.Join(fvDir, name)
		if _, err := os.Stat(src); err != nil {
			return ImageDetails{}, fmt.Errorf("edk2 build: missing %v after build: %w", src, err)
		}
		dst := filepath.Join(params.OutputDir, name)
		if err := osutil.CopyFile(src, dst); err != nil {
			return ImageDetails{}, fmt.Errorf("edk2 build: copy %v -> %v: %w", src, dst, err)
		}
	}

	// Stash a fresh, untouched copy of OVMF_VARS.fd. vm/qemu makes a per-VM
	// copy from this on every launch so SetVariable side-effects from one
	// program do not leak into the next program's flash store. See
	// docs/edk2_design.md §6.7.
	if err := osutil.CopyFile(filepath.Join(fvDir, "OVMF_VARS.fd"),
		filepath.Join(params.OutputDir, "OVMF_VARS.template.fd")); err != nil {
		return ImageDetails{}, fmt.Errorf("edk2 build: stash vars template: %w", err)
	}

	// pkg/build expects KernelObject (sys/targets sets it to OVMF.fd) at
	// OutputDir/obj/<KernelObject>.
	objDir := filepath.Join(params.OutputDir, "obj")
	if err := osutil.MkdirAll(objDir); err != nil {
		return ImageDetails{}, err
	}
	if err := osutil.CopyFile(filepath.Join(fvDir, "OVMF.fd"),
		filepath.Join(objDir, "OVMF.fd")); err != nil {
		return ImageDetails{}, err
	}

	return ImageDetails{}, nil
}

func (ctx edk2) clean(params Params) error {
	buildDir := filepath.Join(params.KernelDir, "Build")
	return os.RemoveAll(buildDir)
}

func (ctx edk2) runShell(params Params, timeout time.Duration, format string, args ...any) ([]byte, error) {
	cmd := fmt.Sprintf(format, args...)
	if !strings.Contains(cmd, ". ./edksetup.sh") {
		// edksetup.sh requires WORKSPACE to point at the source tree; calling
		// it from inside the source tree is what upstream documents.
	}
	return osutil.RunCmd(timeout, params.KernelDir, "/bin/bash", "-c", cmd)
}
