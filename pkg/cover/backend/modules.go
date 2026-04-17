// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package backend

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/sys/targets"
)

// edk2RuntimeAddrs holds the per-driver runtime base addresses parsed
// from "Loading driver at 0x..." messages in the edk2 debug console
// log. vm/qemu.go populates it after the VM reaches SyzFwfuzzRegister
// via SetEdk2RuntimeAddrs(). FixModules consumes it.
//
// Keyed by module name (e.g. "Fat", "DxeCore", "SyzAgentDxe"). For
// single-VM runs the map is global and static; for multi-VM
// configurations the current implementation assumes the addresses
// are identical across boots (which they are for a given OVMF build
// under the same accelerator).
var (
	edk2RuntimeAddrsMu sync.RWMutex
	edk2RuntimeAddrs   map[string]uint64
)

// SetEdk2RuntimeAddrs publishes a name→addr map to FixModules. Called
// from vm/qemu once per boot after the debug log has been parsed.
func SetEdk2RuntimeAddrs(addrs map[string]uint64) {
	edk2RuntimeAddrsMu.Lock()
	defer edk2RuntimeAddrsMu.Unlock()
	edk2RuntimeAddrs = addrs
}

func getEdk2RuntimeAddrs() map[string]uint64 {
	edk2RuntimeAddrsMu.RLock()
	defer edk2RuntimeAddrsMu.RUnlock()
	return edk2RuntimeAddrs
}

func DiscoverModules(target *targets.Target, objDir string, moduleObj []string) (
	[]*vminfo.KernelModule, error) {
	if target.OS == targets.EDK2 {
		return discoverModulesEDK2(objDir)
	}
	module := &vminfo.KernelModule{
		Path: filepath.Join(objDir, target.KernelObject),
	}
	textRange, err := elfReadTextSecRange(module)
	if err != nil {
		return nil, err
	}
	modules := []*vminfo.KernelModule{
		// A dummy module representing the kernel itself.
		{
			Path: module.Path,
			Size: textRange.End - textRange.Start,
		},
	}
	if target.OS == targets.Linux {
		modules1, err := discoverModulesLinux(append([]string{objDir}, moduleObj...))
		if err != nil {
			return nil, err
		}
		modules = append(modules, modules1...)
	} else if len(modules) != 1 {
		return nil, fmt.Errorf("%v coverage does not support modules", target.OS)
	}
	return modules, nil
}

// discoverModulesEDK2 walks the EDK2 build output directory (e.g.
// Build/OvmfX64/NOOPT_GCC5/X64/) and returns every *.dll DXE driver as
// a KernelModule.
//
// EDK2 produces SPLIT DEBUG INFO: each driver has a stripped `.dll`
// next to a full `.debug` sibling containing `.text` + all the
// `.debug_*` sections. The Go `debug/elf` package can't follow
// `.gnu_debuglink` automatically, so we prefer the `.debug` file as
// module.Path when it exists. That file has everything the coverage
// backend needs (text section for PC→module mapping, DWARF for line
// info). Without this fallback, `/cover` in the manager UI returns
// "failed to parse DWARF" and the dashboard shows coverage=0.
//
// Module Size comes from the .text section; the Addr is zero here
// because DXE modules are loaded at dynamic runtime addresses — the
// manager learns those from "Loading driver at 0x..." messages in the
// debug log and calls FixModules to apply the offsets.
func discoverModulesEDK2(objDir string) ([]*vminfo.KernelModule, error) {
	var modules []*vminfo.KernelModule
	err := filepath.WalkDir(objDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if filepath.Ext(path) != ".dll" {
			return nil
		}
		// Skip non-ELF files that happen to have .dll extension (unlikely
		// but possible if EDK2 build produces PE COFF variants).
		f, e := elf.Open(path)
		if e != nil {
			return nil
		}
		f.Close()
		// Prefer the .debug sibling if it exists — that's where the
		// DWARF lives after EDK2's split-debug strip pass.
		modulePath := path
		debugPath := strings.TrimSuffix(path, ".dll") + ".debug"
		if st, statErr := os.Stat(debugPath); statErr == nil && st.Mode().IsRegular() {
			if df, dfErr := elf.Open(debugPath); dfErr == nil {
				df.Close()
				modulePath = debugPath
				log.Logf(2, "edk2: using debug file %v", debugPath)
			}
		} else {
			log.Logf(1, "edk2: no .debug sibling for %v (stat err=%v)", path, statErr)
		}
		name := strings.TrimSuffix(filepath.Base(path), ".dll")
		module := &vminfo.KernelModule{
			Name: name,
			Path: modulePath,
		}
		textRange, e := elfReadTextSecRange(module)
		if e != nil {
			log.Logf(1, "edk2: skipping %v: %v", path, e)
			return nil
		}
		module.Size = textRange.End - textRange.Start
		modules = append(modules, module)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk edk2 build dir %v: %w", objDir, err)
	}
	log.Logf(0, "edk2: discovered %d DXE modules in %v", len(modules), objDir)
	if len(modules) == 0 {
		return nil, fmt.Errorf("no *.dll files found in %v", objDir)
	}
	// Add a dummy "primary module" to match the convention used by
	// the rest of the coverage backend. The first module's path stands
	// in for the "kernel image" since edk2 has no single monolith.
	primary := &vminfo.KernelModule{
		Path: modules[0].Path,
		Size: modules[0].Size,
	}
	return append([]*vminfo.KernelModule{primary}, modules...), nil
}

func discoverModulesLinux(dirs []string) ([]*vminfo.KernelModule, error) {
	paths, err := locateModules(dirs)
	if err != nil {
		return nil, err
	}
	var modules []*vminfo.KernelModule
	for name, path := range paths {
		if path == "" {
			continue
		}
		log.Logf(2, "module %v -> %v", name, path)
		module := &vminfo.KernelModule{
			Name: name,
			Path: path,
		}
		textRange, err := elfReadTextSecRange(module)
		if err != nil {
			return nil, err
		}
		module.Size = textRange.End - textRange.Start
		modules = append(modules, module)
	}
	return modules, nil
}

func locateModules(dirs []string) (map[string]string, error) {
	paths := make(map[string]string)
	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || filepath.Ext(path) != ".ko" {
				return err
			}
			name, err := getModuleName(path)
			if err != nil {
				// Extracting module name involves parsing ELF and binary data,
				// let's not fail on it, we still have the file name,
				// which is usually the right module name.
				log.Logf(0, "failed to get %v module name: %v", path, err)
				name = strings.TrimSuffix(filepath.Base(path), "."+filepath.Ext(path))
			}
			// Order of dirs determine priority, so don't overwrite already discovered names.
			if name != "" && paths[name] == "" {
				paths[name] = path
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return paths, nil
}

func getModuleName(path string) (string, error) {
	file, err := elf.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	section := file.Section(".modinfo")
	if section == nil {
		return "", fmt.Errorf("no .modinfo section")
	}
	data, err := section.Data()
	if err != nil {
		return "", fmt.Errorf("failed to read .modinfo: %w", err)
	}
	if name := searchModuleName(data); name != "" {
		return name, nil
	}
	section = file.Section(".gnu.linkonce.this_module")
	if section == nil {
		return "", fmt.Errorf("no .gnu.linkonce.this_module section")
	}
	data, err = section.Data()
	if err != nil {
		return "", fmt.Errorf("failed to read .gnu.linkonce.this_module: %w", err)
	}
	return string(data), nil
}

func searchModuleName(data []byte) string {
	data = append([]byte{0}, data...)
	key := []byte("\x00name=")
	pos := bytes.Index(data, key)
	if pos == -1 {
		return ""
	}
	end := bytes.IndexByte(data[pos+len(key):], 0)
	if end == -1 {
		return ""
	}
	end = pos + len(key) + end
	if end > len(data) {
		return ""
	}
	return string(data[pos+len(key) : end])
}

func getKaslrOffset(modules []*vminfo.KernelModule, pcBase uint64) uint64 {
	for _, mod := range modules {
		if mod.Name == "" {
			return mod.Addr - pcBase
		}
	}
	return 0
}

// when CONFIG_RANDOMIZE_BASE=y, pc from kcov already removed kaslr_offset.
func FixModules(localModules, modules []*vminfo.KernelModule, pcBase uint64) []*vminfo.KernelModule {
	// If the VM didn't report any runtime modules (e.g. edk2 HostFuzzer,
	// where there's no guest-side module enumeration), fall back to the
	// compile-time localModules list. When vm/qemu has parsed "Loading
	// driver at 0x..." lines from the edk2 debug log and published the
	// per-name runtime addresses via SetEdk2RuntimeAddrs(), apply those
	// to populate each module.Addr — otherwise all modules have Addr=0
	// and runtime PCs never fall into their ranges.
	if len(modules) == 0 {
		addrs := getEdk2RuntimeAddrs()
		if len(addrs) == 0 {
			return localModules
		}
		out := make([]*vminfo.KernelModule, 0, len(localModules))
		for _, lm := range localModules {
			addr, ok := addrs[lm.Name]
			if !ok {
				continue // driver wasn't loaded this boot
			}
			out = append(out, &vminfo.KernelModule{
				Name: lm.Name,
				Size: lm.Size,
				Addr: addr,
				Path: lm.Path,
			})
		}
		return out
	}
	kaslrOffset := getKaslrOffset(modules, pcBase)
	var modules1 []*vminfo.KernelModule
	for _, mod := range modules {
		size := uint64(0)
		path := ""
		for _, modA := range localModules {
			if modA.Name == mod.Name {
				size = modA.Size
				path = modA.Path
				break
			}
		}
		if path == "" {
			continue
		}
		addr := mod.Addr - kaslrOffset
		modules1 = append(modules1, &vminfo.KernelModule{
			Name: mod.Name,
			Size: size,
			Addr: addr,
			Path: path,
		})
	}
	return modules1
}
