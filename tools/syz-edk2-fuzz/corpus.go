// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Coverage-guided corpus for the standalone syz-edk2-fuzz driver.
//
// The "real" syz-manager has a sophisticated corpus pipeline involving
// triage, deflaking, minimization, and prio-weighted choice tables. This
// file implements a simple version suited to the standalone tool:
//
//   - Track unique firmware PCs across iterations.
//   - When a new program adds NEW PCs to the global coverage set, save
//     the program (as a *prog.Prog so it can be re-mutated later).
//   - Each iteration, with some probability, mutate an existing corpus
//     entry instead of generating a fresh random program. This is the
//     single biggest win over independent random generation.
//   - Persist the corpus to a file on disk so campaign restarts resume
//     with the accumulated coverage.
//
// The persistence format is simple: one serialized syzlang program per
// line (gzip-compressed to save space, plus a small header). The prog
// package's Serialize/Deserialize handles the heavy lifting.

package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"math/rand"
	"os"
	"sync"

	"github.com/google/syzkaller/prog"
)

// corpusEntry is one program in the corpus.
type corpusEntry struct {
	prog    *prog.Prog         // the syzkaller program (for re-mutation)
	pcs     map[uint64]struct{} // unique firmware PCs this program hit
	score   int                // number of unique PCs (tiebreaker for selection)
}

// fuzzCorpus is the coverage-guided corpus manager. It is goroutine-safe.
type fuzzCorpus struct {
	mu       sync.Mutex
	entries  []*corpusEntry
	allPCs   map[uint64]struct{} // global max PC set
	path     string              // on-disk persistence file
	savedGen int                 // entries saved to disk; entries >= savedGen need flushing
}

func newFuzzCorpus(path string) *fuzzCorpus {
	return &fuzzCorpus{
		allPCs: make(map[uint64]struct{}),
		path:   path,
	}
}

// Len returns the number of corpus entries.
func (fc *fuzzCorpus) Len() int {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return len(fc.entries)
}

// TotalPCs returns the global unique PC count.
func (fc *fuzzCorpus) TotalPCs() int {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return len(fc.allPCs)
}

// MaybeAdd checks if `newPCs` contains PCs not already in the global set,
// and if so, stores the program as a new corpus entry. Returns true if
// the program was added.
func (fc *fuzzCorpus) MaybeAdd(p *prog.Prog, newPCs []uint64) bool {
	if p == nil || len(newPCs) == 0 {
		return false
	}
	fc.mu.Lock()
	defer fc.mu.Unlock()

	uniqToThis := make(map[uint64]struct{}, len(newPCs))
	newCount := 0
	for _, pc := range newPCs {
		if _, ok := fc.allPCs[pc]; !ok {
			fc.allPCs[pc] = struct{}{}
			uniqToThis[pc] = struct{}{}
			newCount++
		}
	}
	if newCount == 0 {
		return false
	}
	// Also include already-known PCs this program hit, up to a cap,
	// so mutation has a fuller PC set to work with.
	for _, pc := range newPCs {
		if _, has := uniqToThis[pc]; !has {
			uniqToThis[pc] = struct{}{}
		}
		if len(uniqToThis) > 4096 {
			break
		}
	}
	fc.entries = append(fc.entries, &corpusEntry{
		prog:  p.Clone(),
		pcs:   uniqToThis,
		score: newCount,
	})
	return true
}

// PickForMutation returns a random corpus entry, or nil if the corpus
// is empty. Selection is weighted by the entry's score (newer/larger
// coverage entries are more likely to be picked).
func (fc *fuzzCorpus) PickForMutation(rng *rand.Rand) *prog.Prog {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if len(fc.entries) == 0 {
		return nil
	}
	// Simple weighted selection: total weight = sum of scores.
	totalWeight := 0
	for _, e := range fc.entries {
		totalWeight += e.score
	}
	if totalWeight == 0 {
		return fc.entries[rng.Intn(len(fc.entries))].prog.Clone()
	}
	pick := rng.Intn(totalWeight)
	for _, e := range fc.entries {
		pick -= e.score
		if pick < 0 {
			return e.prog.Clone()
		}
	}
	return fc.entries[len(fc.entries)-1].prog.Clone()
}

// Save writes the current corpus to the persistence file. Overwrites
// any existing file.
func (fc *fuzzCorpus) Save() error {
	if fc.path == "" {
		return nil
	}
	fc.mu.Lock()
	defer fc.mu.Unlock()

	tmp := fc.path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(f)
	bw := bufio.NewWriter(gz)

	// Simple line-based format: each line starts with "PROG:" followed
	// by a base64-style escape of the serialized program. Using
	// fmt.Fprintln with newline separator.
	fmt.Fprintln(bw, "# syz-edk2-fuzz corpus v1")
	fmt.Fprintf(bw, "# %d entries, %d total PCs\n", len(fc.entries), len(fc.allPCs))
	for _, e := range fc.entries {
		serialized := e.prog.Serialize()
		// Escape newlines in the serialized form by replacing with a
		// known delimiter. Actually the prog serialization uses \n
		// internally, so we wrap each prog in a length-prefixed block.
		fmt.Fprintf(bw, "BEGIN %d\n", len(serialized))
		bw.Write(serialized)
		fmt.Fprintln(bw, "END")
	}
	bw.Flush()
	gz.Close()
	f.Close()
	return os.Rename(tmp, fc.path)
}

// Load reads the persistence file and populates the corpus. Missing
// files are not an error.
func (fc *fuzzCorpus) Load(gt *grammarTarget) error {
	if fc.path == "" {
		return nil
	}
	f, err := os.Open(fc.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	br := bufio.NewReader(gz)
	loaded := 0
	for {
		line, err := br.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		var size int
		if _, err := fmt.Sscanf(line, "BEGIN %d", &size); err != nil {
			// Skip comments / other lines
			continue
		}
		buf := make([]byte, size)
		if _, err := io.ReadFull(br, buf); err != nil {
			return fmt.Errorf("short read on program body: %w", err)
		}
		// Discard the "END" marker line
		if _, err := br.ReadString('\n'); err != nil {
			return err
		}
		if _, err := br.ReadString('\n'); err != nil && err != io.EOF {
			return err
		}
		p, err := gt.target.Deserialize(buf, prog.NonStrict)
		if err != nil {
			// Skip unparseable entries (grammar may have evolved)
			continue
		}
		fc.mu.Lock()
		fc.entries = append(fc.entries, &corpusEntry{
			prog:  p,
			pcs:   map[uint64]struct{}{},
			score: 1,
		})
		fc.mu.Unlock()
		loaded++
	}
	fmt.Fprintf(os.Stderr, "[corpus] loaded %d entries from %s\n", loaded, fc.path)
	return nil
}

// mutateGrammarProgram picks a corpus entry and mutates it, returning
// a wire-format program. Falls back to random generation if the corpus
// is empty.
func (gt *grammarTarget) mutateGrammarProgram(rng *rand.Rand, fc *fuzzCorpus) (*program, *prog.Prog, error) {
	parent := fc.PickForMutation(rng)
	if parent == nil {
		// Corpus empty; generate fresh
		return gt.generateGrammarProgramWithProg(rng)
	}
	// Mutate the parent in-place
	child := parent.Clone()
	rs := rand.NewSource(rng.Int63())
	child.Mutate(rs, 1, gt.ct, nil, nil)
	// Walk the mutated program
	for _, call := range child.Calls {
		if call.Meta.Name != "syz_edk2_run_program" {
			continue
		}
		wire, err := walkSyzEdk2RunProgram(call, child)
		if err != nil {
			// If mutation produced something we can't walk, try once more
			// with a fresh random program.
			return gt.generateGrammarProgramWithProg(rng)
		}
		return wire, child, nil
	}
	return gt.generateGrammarProgramWithProg(rng)
}

// generateGrammarProgramWithProg is a variant of generateGrammarProgram
// that also returns the underlying *prog.Prog so the corpus can store
// it. (The existing generateGrammarProgram throws the *prog.Prog away.)
func (gt *grammarTarget) generateGrammarProgramWithProg(rng *rand.Rand) (*program, *prog.Prog, error) {
	rs := rand.NewSource(rng.Int63())
	p := gt.target.Generate(rs, 1, gt.ct)
	for _, call := range p.Calls {
		if call.Meta.Name != "syz_edk2_run_program" {
			continue
		}
		wire, err := walkSyzEdk2RunProgram(call, p)
		if err != nil {
			return nil, nil, err
		}
		return wire, p, nil
	}
	return nil, nil, fmt.Errorf("prog.Generate did not pick syz_edk2_run_program")
}

// Suppress unused imports when bytes isn't needed elsewhere.
var _ = bytes.NewBuffer
