// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Grammar-driven program generation for the edk2 target.
//
// In -use-grammar mode the fuzzer asks the syzkaller prog package to
// build a *prog.Prog from the sys/edk2/edk2.txt syzlang descriptions
// (the same path syz-manager would take), then walks the resulting
// argument tree and translates it to the SyzAgent wire format. This
// gives us:
//
//   - Real syzlang struct/array layouts (sizes, len fields, packed
//     padding, flag values).
//   - The full set of syz_edk2_call variants the description defines,
//     even ones I forgot about in the hand-rolled emitter.
//   - A natural place to plug in mutation, choice tables, and corpus
//     persistence later (Path 1 in the previous summary).
//
// What this file does NOT do today:
//
//   - Coverage-guided mutation. Each iteration is an independent
//     target.Generate() call with the default choice table. This is
//     "grammar-aware random", not full syzkaller fuzzing.
//   - Resource chaining across calls. We only ever generate single-call
//     programs (one syz_edk2_run_program), so there are no resources to
//     plumb between calls. The agent's allocation slots take that role.
//
// The translator is intentionally narrow: it only knows how to walk
// the specific shape sys/edk2/edk2.txt produces (one
// syz_edk2_run_program with one ptr -> edk2_program -> array of
// syz_edk2_call). If the grammar grows new top-level shapes, this file
// needs to learn them.

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

// grammarSkipIDs is a debug knob set from main.go via -grammar-skip;
// any union variant whose call ID is in the set is dropped before
// emitting. Used to bisect "which new handler hangs the agent".
var grammarSkipIDs map[uint32]bool

// grammarTarget is initialized once via getGrammarTarget(); it holds
// the prog.Target for edk2/amd64 plus a default choice table.
type grammarTarget struct {
	target *prog.Target
	ct     *prog.ChoiceTable
}

func unionVariantID(u *prog.UnionArg) uint32 {
	apiStruct, ok := u.Option.(*prog.GroupArg)
	if !ok || len(apiStruct.Inner) < 1 {
		return 0
	}
	if c, ok := apiStruct.Inner[0].(*prog.ConstArg); ok {
		return uint32(c.Val)
	}
	return 0
}

func getGrammarTarget() (*grammarTarget, error) {
	t, err := prog.GetTarget("edk2", "amd64")
	if err != nil {
		return nil, fmt.Errorf("prog.GetTarget(edk2/amd64): %w", err)
	}
	return &grammarTarget{
		target: t,
		ct:     t.DefaultChoiceTable(),
	}, nil
}

// generateGrammarProgram returns one wire-format edk2 program produced
// by the syzkaller prog generator. The returned (numCalls, wire) pair
// can be fed straight into pokeAgent().
func (gt *grammarTarget) generateGrammarProgram(rng *rand.Rand) (*program, error) {
	// Generate a syzkaller program with exactly one call. The
	// description defines syz_edk2_run_program as the only entry
	// point, so prog.Generate will pick it.
	rs := rand.NewSource(rng.Int63())
	p := gt.target.Generate(rs, 1, gt.ct)
	for _, call := range p.Calls {
		if call.Meta.Name != "syz_edk2_run_program" {
			continue
		}
		return walkSyzEdk2RunProgram(call, p)
	}
	return nil, fmt.Errorf("prog.Generate did not pick syz_edk2_run_program")
}

// walkSyzEdk2RunProgram extracts the inner edk2_program from a
// syz_edk2_run_program *prog.Call and converts it to wire format.
func walkSyzEdk2RunProgram(call *prog.Call, p *prog.Prog) (*program, error) {
	if len(call.Args) < 1 {
		return nil, fmt.Errorf("syz_edk2_run_program: no args")
	}
	ptr, ok := call.Args[0].(*prog.PointerArg)
	if !ok {
		return nil, fmt.Errorf("syz_edk2_run_program: arg0 not PointerArg")
	}
	if ptr.Res == nil {
		return nil, fmt.Errorf("syz_edk2_run_program: arg0 ptr Res is nil")
	}
	progStruct, ok := ptr.Res.(*prog.GroupArg)
	if !ok {
		return nil, fmt.Errorf("syz_edk2_run_program: arg0 pointee not GroupArg")
	}
	// edk2_program: { magic, ncalls, calls (array of union) }
	if len(progStruct.Inner) < 3 {
		return nil, fmt.Errorf("edk2_program: only %d inner fields", len(progStruct.Inner))
	}
	callsArray, ok := progStruct.Inner[2].(*prog.GroupArg)
	if !ok {
		return nil, fmt.Errorf("edk2_program.calls not GroupArg")
	}

	var buf bytes.Buffer
	numCalls := 0
	for _, item := range callsArray.Inner {
		u, ok := item.(*prog.UnionArg)
		if !ok {
			continue
		}
		// Optional: drop variants whose ID is in a denylist (debug).
		if id := unionVariantID(u); grammarSkipIDs != nil && grammarSkipIDs[id] {
			continue
		}
		if err := emitUnionVariant(&buf, u); err != nil {
			// Skip variants we can't translate yet — better to
			// emit a partial program than to fail the iteration.
			continue
		}
		numCalls++
		if numCalls >= edk2MaxCalls {
			break
		}
		if buf.Len() > edk2MaxProgramBytes-128 {
			break
		}
	}
	if numCalls == 0 {
		return nil, fmt.Errorf("no translatable variants in edk2_program")
	}
	syzText := ""
	if flagSyzProg != nil && *flagSyzProg {
		syzText = string(p.Serialize())
	}
	return &program{NumCalls: numCalls, Wire: buf.Bytes(), SyzProg: syzText}, nil
}

// emitUnionVariant translates one syz_edk2_call union variant into a
// wire-format (call, size, payload) record. The Option of the union is
// expected to be a GroupArg laid out by the syz_edk2_api template:
//
//	{ call: const[NUM, int32], size: bytesize[parent, int32], payload: PAYLOAD }
//
// We read the call ID from the first field, recompute the size
// ourselves (the prog package may set it before resolving lengths),
// and serialize payload byte-for-byte.
func emitUnionVariant(buf *bytes.Buffer, u *prog.UnionArg) error {
	apiStruct, ok := u.Option.(*prog.GroupArg)
	if !ok {
		return fmt.Errorf("union option is not GroupArg")
	}
	if len(apiStruct.Inner) < 3 {
		return fmt.Errorf("syz_edk2_api struct has %d fields", len(apiStruct.Inner))
	}
	callIDArg, ok := apiStruct.Inner[0].(*prog.ConstArg)
	if !ok {
		return fmt.Errorf("syz_edk2_api.call not ConstArg")
	}
	callID := uint32(callIDArg.Val)

	var payBuf bytes.Buffer
	if err := serializeArg(&payBuf, apiStruct.Inner[2]); err != nil {
		return err
	}

	// Wire-format header is exactly 8 bytes.
	binary.Write(buf, binary.LittleEndian, callID)
	binary.Write(buf, binary.LittleEndian, uint32(8+payBuf.Len()))
	buf.Write(payBuf.Bytes())
	return nil
}

// serializeArg writes the byte representation of a prog.Arg into buf
// the same way the EDK2-side C struct casts would expect to read it.
// Only the cases the edk2.txt grammar can produce are handled.
func serializeArg(buf *bytes.Buffer, a prog.Arg) error {
	switch x := a.(type) {
	case *prog.ConstArg:
		val, _ := x.Value()
		switch x.Size() {
		case 1:
			buf.WriteByte(byte(val))
		case 2:
			binary.Write(buf, binary.LittleEndian, uint16(val))
		case 4:
			binary.Write(buf, binary.LittleEndian, uint32(val))
		case 8:
			binary.Write(buf, binary.LittleEndian, val)
		default:
			return fmt.Errorf("ConstArg with unexpected size %d", x.Size())
		}
	case *prog.GroupArg:
		for _, inner := range x.Inner {
			if err := serializeArg(buf, inner); err != nil {
				return err
			}
		}
	case *prog.UnionArg:
		return serializeArg(buf, x.Option)
	case *prog.DataArg:
		buf.Write(x.Data())
	case *prog.PointerArg:
		// We don't expect inner pointers in our wire format, but if
		// the prog package emits one, follow it.
		if x.Res != nil {
			return serializeArg(buf, x.Res)
		}
	case *prog.ResultArg:
		// Resources aren't used in our edk2 grammar — write zero.
		switch x.Size() {
		case 1:
			buf.WriteByte(0)
		case 2:
			binary.Write(buf, binary.LittleEndian, uint16(0))
		case 4:
			binary.Write(buf, binary.LittleEndian, uint32(0))
		case 8:
			binary.Write(buf, binary.LittleEndian, uint64(0))
		}
	default:
		return fmt.Errorf("unsupported Arg type %T", a)
	}
	return nil
}
