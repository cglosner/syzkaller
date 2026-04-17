// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// fwsnap.go — host-side bindings for the cglosner/qemu-fwfuzz
// contrib/plugins/libfwsnap.so plugin. The plugin owns a SysV shared
// memory segment laid out as:
//
//   Offset  Size  Field
//   ------  ----  ---------------------------------------------------
//      0       1  command           (host -> plugin)
//      1       1  status            (plugin -> host)
//      2       6  reserved
//      8       8  fuzz_input_addr   (host -> plugin) physical address
//     16       8  fuzz_input_len    (host -> plugin) byte count to copy
//     24       8  iter_block_count  (plugin -> host) TBs in this iteration
//     32       8  exit_reason       (plugin -> host)
//     40      24  reserved
//     64       N  fuzz_input_data[fuzz_max]  (host writes here)
//
// This file creates the shmem segment from Go, passes its id to qemu,
// and provides write/restore/wait helpers so the fuzz loop can drive
// the plugin. Used only when -tcg-snapshot is enabled.

package main

import (
	"encoding/binary"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// Command / status constants copied from contrib/plugins/fwsnap.c.
const (
	fwsnapCmdNop      = 0
	fwsnapCmdRestore  = 1
	fwsnapCmdSnapshot = 2
	fwsnapCmdExit     = 3

	fwsnapStatusIdle      = 0
	fwsnapStatusRunning   = 1
	fwsnapStatusSnapReady = 2
	fwsnapStatusRestored  = 3
	fwsnapStatusDone      = 4

	fwsnapExitNormal  = 0
	fwsnapExitTimeout = 1
	fwsnapExitCrash   = 2

	fwsnapHeaderSize = 64
)

// Field offsets within the shmem segment. Must match FwSnapControl in
// contrib/plugins/fwsnap.c exactly.
const (
	fwsnapOffCommand      = 0
	fwsnapOffStatus       = 1
	fwsnapOffFuzzInputAdr = 8
	fwsnapOffFuzzInputLen = 16
	fwsnapOffIterBlocks   = 24
	fwsnapOffExitReason   = 32
	fwsnapOffShadowBase   = 40
	fwsnapOffShadowSize   = 48
	fwsnapOffFuzzData     = 64
)

// fwsnap holds a SysV shmem segment attached to the host.
type fwsnap struct {
	id     int    // SysV shmid (passed to plugin via shmid= option)
	mem    []byte // attached memory view
	fmax   int    // fuzz_max (size of the data area after the header)
}

// newFwsnap creates a new SysV shmem segment of size headerSize+fuzzMax
// and attaches it into the caller's address space.
func newFwsnap(fuzzMax int) (*fwsnap, error) {
	total := fwsnapHeaderSize + fuzzMax
	// IPC_PRIVATE, rw-rw-rw-
	id, err := unix.SysvShmGet(unix.IPC_PRIVATE, total, 0o666|unix.IPC_CREAT)
	if err != nil {
		return nil, fmt.Errorf("SysvShmGet: %w", err)
	}
	mem, err := unix.SysvShmAttach(id, 0, 0)
	if err != nil {
		_, _ = unix.SysvShmCtl(id, unix.IPC_RMID, nil)
		return nil, fmt.Errorf("SysvShmAttach(%d): %w", id, err)
	}
	// Zero the header and the data area.
	for i := range mem {
		mem[i] = 0
	}
	return &fwsnap{id: id, mem: mem, fmax: fuzzMax}, nil
}

// ShmId returns the SysV shmid for the plugin command line.
func (f *fwsnap) ShmId() int {
	return f.id
}

// Close detaches from the segment and removes it.
func (f *fwsnap) Close() {
	if f == nil || f.mem == nil {
		return
	}
	_ = unix.SysvShmDetach(f.mem)
	_, _ = unix.SysvShmCtl(f.id, unix.IPC_RMID, nil)
	f.mem = nil
}

// readStatus returns the plugin status byte.
func (f *fwsnap) readStatus() uint8 {
	return f.mem[fwsnapOffStatus]
}

// readCommand returns the pending command byte.
func (f *fwsnap) readCommand() uint8 {
	return f.mem[fwsnapOffCommand]
}

// writeCommand stores a command byte for the plugin. The plugin picks
// it up on the next TB exec and resets it to NOP after handling.
func (f *fwsnap) writeCommand(cmd uint8) {
	f.mem[fwsnapOffCommand] = cmd
}

// SetShadowRegion publishes the ASan shadow region base/size to the
// plugin. The plugin picks these up on the next snapshot and adds them
// as a dynamic memory region, so subsequent restores roll the shadow
// back to its snapshot state.
func (f *fwsnap) SetShadowRegion(base, size uint64) {
	binary.LittleEndian.PutUint64(f.mem[fwsnapOffShadowBase:], base)
	binary.LittleEndian.PutUint64(f.mem[fwsnapOffShadowSize:], size)
}

// SetFuzzInput writes data into the fuzz input buffer and tells the
// plugin where to inject it in the guest.
func (f *fwsnap) SetFuzzInput(guestPhysAddr uint64, data []byte) error {
	if len(data) > f.fmax {
		return fmt.Errorf("fuzz input %d bytes exceeds fuzz_max=%d", len(data), f.fmax)
	}
	binary.LittleEndian.PutUint64(f.mem[fwsnapOffFuzzInputAdr:], guestPhysAddr)
	binary.LittleEndian.PutUint64(f.mem[fwsnapOffFuzzInputLen:], uint64(len(data)))
	copy(f.mem[fwsnapOffFuzzData:], data)
	return nil
}

// SendRestore triggers a snapshot restore. Before calling this the
// host should have written the fresh fuzz input via SetFuzzInput.
// Returns once the plugin acknowledges RESTORED status (or on timeout).
func (f *fwsnap) SendRestore(timeout time.Duration) error {
	f.writeCommand(fwsnapCmdRestore)
	// Wait for the plugin to accept the command. It zeroes the command
	// byte after acting on it.
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if f.readCommand() == fwsnapCmdNop {
			return nil
		}
		time.Sleep(100 * time.Microsecond)
	}
	return fmt.Errorf("fwsnap: RESTORE command not acknowledged within %v", timeout)
}

// SendSnapshot tells the plugin to take a fresh snapshot on the next TB.
func (f *fwsnap) SendSnapshot(timeout time.Duration) error {
	f.writeCommand(fwsnapCmdSnapshot)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if f.readCommand() == fwsnapCmdNop {
			return nil
		}
		time.Sleep(100 * time.Microsecond)
	}
	return fmt.Errorf("fwsnap: SNAPSHOT command not acknowledged within %v", timeout)
}

// WaitStatus polls until the plugin reports one of the given statuses,
// or the timeout expires. Returns the final status (or the last one
// seen on timeout).
func (f *fwsnap) WaitStatus(timeout time.Duration, want ...uint8) (uint8, error) {
	deadline := time.Now().Add(timeout)
	var last uint8
	for time.Now().Before(deadline) {
		last = f.readStatus()
		for _, w := range want {
			if last == w {
				return last, nil
			}
		}
		time.Sleep(100 * time.Microsecond)
	}
	return last, fmt.Errorf("fwsnap: timed out waiting for status %v (last=%d)", want, last)
}

// IterBlockCount returns the TB count the plugin recorded for the
// last iteration (populated when status transitions to DONE).
func (f *fwsnap) IterBlockCount() uint64 {
	return binary.LittleEndian.Uint64(f.mem[fwsnapOffIterBlocks:])
}

// ExitReason returns the exit reason word (0=normal, 1=timeout, 2=crash).
func (f *fwsnap) ExitReason() uint64 {
	return binary.LittleEndian.Uint64(f.mem[fwsnapOffExitReason:])
}
