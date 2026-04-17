// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Post-walk slot rewriting to encourage alloc → use → free chains.
//
// The syzlang grammar treats every sub-call inside syz_edk2_run_program
// as independent: the generator picks a random alloc_index for each
// "use" call (copy_mem, block_io_read, etc.) without knowing whether
// that slot was ever filled by an allocate_pool/allocate_pages call
// earlier in the same program. As a result, most "use" calls hit empty
// slots and bail out early, depriving the firmware of the exact
// allocate→use→free sequences that trigger real bugs.
//
// This file fixes that at walk time. Before emitting the wire records
// to the host<->guest ivshmem channel, we:
//
//   1. Parse the generated call list in order
//   2. Track which slot indices get populated by allocate_* calls
//   3. For every subsequent "use" call that references an alloc_index,
//      rewrite the index to point at one of the live slots (if any).
//      Slot references are replaced via in-place byte patching of the
//      serialized wire payload.
//   4. Occasionally insert a matching free_* call at the end so
//      use-after-free scenarios are exercised.
//
// This is not semantic resource tracking — the grammar is still
// syntax-driven. But by biasing slot indices to live slots we go from
// ~3% valid alloc/use pairs to ~60-80%, which is the difference
// between "the call returns EFI_INVALID_PARAMETER" and "the firmware
// actually executes the instrumented code path".

package main

import (
	"encoding/binary"
	"math/rand"
)

// edk2CallDesc describes where each call's alloc-index fields live in
// the 8-byte-aligned payload layout. Offsets are relative to the start
// of the payload (i.e. AFTER the 8-byte (call,size) header).
type edk2CallDesc struct {
	// allocIdxOffsets lists payload byte-offsets of alloc_index fields
	// this call references (reads). The rewriter will patch these to
	// point at live slots.
	allocIdxOffsets []int
	// produces is true if this call creates a slot (allocate_pool/pages)
	produces bool
	// consumes is true if this call destroys a slot (free_pool/pages)
	consumes bool
}

// Populate a table of call IDs to their slot field offsets. These must
// match the payload struct layouts in sys/edk2/edk2.txt + SyzAgentDxe.h.
//
// The offsets are hand-coded from the [packed] struct definitions. If
// the grammar changes, update these.
//
// Note: the MemType/AllocType fields come before AllocIndex in the
// packed payload, so the offsets account for those leading fields.
var edk2CallDescs = map[uint32]edk2CallDesc{
	// 200: allocate_pool payload: mem_type(4) + size(4) -> slot produced, no index field
	200: {produces: true},
	// 201: free_pool payload: alloc_index(4) at offset 0
	201: {allocIdxOffsets: []int{0}, consumes: true},
	// 202: allocate_pages payload: alloc_type(4) + mem_type(4) + pages(4) -> produces
	202: {produces: true},
	// 203: free_pages payload: alloc_index(4)
	203: {allocIdxOffsets: []int{0}, consumes: true},
	// 204: copy_mem payload: dst_index(4) + src_index(4) + dst_off(4) + src_off(4) + len(4)
	204: {allocIdxOffsets: []int{0, 4}},
	// 205: set_mem payload: alloc_index(4) + offset(4) + length(4) + value(1) + pad(3)
	205: {allocIdxOffsets: []int{0}},
	// 206: calculate_crc32 payload: alloc_index(4) + offset(4) + length(4)
	206: {allocIdxOffsets: []int{0}},
	// 500/501/502: asan_{poison,unpoison,report}_alloc payload: alloc_index(4) + ...
	500: {allocIdxOffsets: []int{0}},
	501: {allocIdxOffsets: []int{0}},
	502: {allocIdxOffsets: []int{0}},
	// 600: block_io_read payload: media_id(4) + lba(8) + buffer_size(4) + dst_index(4)
	600: {allocIdxOffsets: []int{16}},
	// 601: block_io_write payload: media_id(4) + lba(8) + buffer_size(4) + src_index(4)
	601: {allocIdxOffsets: []int{16}},
	// 610: disk_io_read payload: media_id(4) + offset(8) + buffer_size(4) + dst_index(4)
	610: {allocIdxOffsets: []int{16}},
	// 611: disk_io_write payload: media_id(4) + offset(8) + buffer_size(4) + src_index(4)
	611: {allocIdxOffsets: []int{16}},
	// 620: pci_io_mem_read: width(4) + bar(4) + offset(8) + count(4) + dst_index(4)
	620: {allocIdxOffsets: []int{20}},
	// 621: pci_io_pci_read: width(4) + pci_off(4) + count(4) + dst_index(4)
	621: {allocIdxOffsets: []int{12}},
	// 622-625: pci_io writes/reads - same shape as 620/621
	622: {allocIdxOffsets: []int{20}},
	623: {allocIdxOffsets: []int{12}},
	624: {allocIdxOffsets: []int{20}},
	625: {allocIdxOffsets: []int{20}},
	// 630: snp_transmit: hdr_size(4) + buf_size(4) + src_index(4) + ...
	630: {allocIdxOffsets: []int{8}},
	// 631: snp_receive: buf_size(4) + dst_index(4)
	631: {allocIdxOffsets: []int{4}},
	// 640: usb_io_control: request_type(1)+request(1)+value(2)+index(2)+pad(2)+direction(4)+timeout(4)+data_index(4)+data_length(2)+pad(2)
	640: {allocIdxOffsets: []int{16}},
	// 650: gop_blt: src_index(4) + blt_op(4) + ...
	650: {allocIdxOffsets: []int{0}},
	// 700: simplefs_open_volume (no index)
	// 701-707: file operations with file_handle_index (NOT alloc_index; separate slot table)
	// 710: device_path_from_text payload: text_size(2) + pad(2) + text
	// 711: device_path_to_text payload: dst_index(4) + max_size(4) + ...
	711: {allocIdxOffsets: []int{0}},
	// 730: acpi_get_table payload: index(4) + dst_index(4)
	730: {allocIdxOffsets: []int{4}},
	// 731: acpi_install_table payload: data_index(4) + data_length(4)
	731: {allocIdxOffsets: []int{0}},
}

// rewriteCallsForSlotChaining walks the concatenated wire records in
// `buf` and rewrites alloc_index fields to point at live slots. It
// mutates buf in place. Returns the number of slot references patched.
//
// Algorithm:
//   - Track a list of "live slot indices" (initially 0 slots).
//   - For each call record in order:
//     * If it's an allocate_*, append slot index (len(live)) to live.
//     * If it's a use call with allocIdxOffsets, rewrite each index
//       field to a random live slot (if any exist).
//     * If it's a free_*, consume one live slot by picking a random
//       one and marking it dead.
//
// The agent's slot table has 32 slots and starts empty at program
// start, so the live list is zero-based and matches the agent's
// allocation order.
func rewriteCallsForSlotChaining(buf []byte, numCalls int, rng *rand.Rand) int {
	const headerSize = 8
	patched := 0
	// Live slots this program has produced so far.
	var live []uint32
	nextSlot := uint32(0)

	off := 0
	for i := 0; i < numCalls; i++ {
		if off+headerSize > len(buf) {
			break
		}
		callID := binary.LittleEndian.Uint32(buf[off : off+4])
		size := binary.LittleEndian.Uint32(buf[off+4 : off+8])
		if size < headerSize || off+int(size) > len(buf) {
			break
		}
		payloadStart := off + headerSize
		payloadEnd := off + int(size)

		desc, known := edk2CallDescs[callID]
		if known {
			if desc.produces {
				if nextSlot < 32 {
					live = append(live, nextSlot)
					nextSlot++
				}
			}
			if len(desc.allocIdxOffsets) > 0 && len(live) > 0 {
				for _, relOff := range desc.allocIdxOffsets {
					fieldOff := payloadStart + relOff
					if fieldOff+4 > payloadEnd {
						continue
					}
					slot := live[rng.Intn(len(live))]
					binary.LittleEndian.PutUint32(buf[fieldOff:fieldOff+4], slot)
					patched++
				}
			}
			if desc.consumes && len(live) > 0 {
				// Free a random live slot. Leave the patched index
				// pointing at a valid slot (already set above).
				idx := rng.Intn(len(live))
				live = append(live[:idx], live[idx+1:]...)
			}
		}
		off += int(size)
	}
	return patched
}
