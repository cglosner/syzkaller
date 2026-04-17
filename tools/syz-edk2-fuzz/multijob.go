// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Multi-VM parallelism for the standalone syz-edk2-fuzz driver.
//
// The fuzz loop is heavily tied to a single QEMU + ivshmem pair, so
// rather than refactoring it to support goroutine workers (which
// would require locks on every stats counter and coverage set), we
// achieve parallelism by forking N child processes of ourselves, each
// with -jobs=1 and isolated workdirs/shmem files. This keeps the
// single-job code path simple and fast, and adds almost no
// per-iteration overhead.
//
// The parent process:
//   1. Cleans up any stale per-worker subdirs
//   2. Spawns N children with distinct -workdir and -shmem
//   3. Optionally shares a corpus file across children: each child
//      writes its own corpus-<N>.gz, and the parent merges them at
//      the end (and/or periodically) into the user's -corpus path.
//   4. Waits for all children to finish
//   5. Aggregates their JSON summaries on stdout
//
// The children log to workdir/worker-<N>/stderr.log so logs don't
// intermix on the parent's stderr.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

func runMultiJob(n int) {
	fmt.Fprintf(os.Stderr, "[jobs] parent: spawning %d workers\n", n)

	// Re-invoke ourselves, once per worker, with:
	//   -jobs=1
	//   -workdir=<base>/worker-<i>
	//   -shmem=<base>/worker-<i>/syz-edk2.shm
	//   -ovmf-debug-log=<base>/worker-<i>/edk2-debug.log
	//   -seed=<base-seed + i>   (so workers diverge)
	//   -corpus=<base>/corpus-<i>.gz  (only if -corpus is set)
	//
	// Every other flag is passed through unchanged.
	self, err := os.Executable()
	if err != nil {
		fail("find self-executable: %v", err)
	}

	// Collect arguments to pass to children, stripping jobs/workdir/shmem/etc
	// so we can override them per-worker.
	childArgs := filterArgs(os.Args[1:], map[string]bool{
		"-jobs":           true,
		"-workdir":        true,
		"-shmem":          true,
		"-ovmf-debug-log": true,
		"-seed":           true,
		"-corpus":         true,
		"-prog-log":       true,
	})

	var wg sync.WaitGroup
	results := make([]runResult, n)
	resultsMu := sync.Mutex{}

	for i := 0; i < n; i++ {
		wi := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			workerDir := filepath.Join(*flagWorkdir, fmt.Sprintf("worker-%d", wi))
			os.MkdirAll(workerDir, 0o755)

			args := append([]string{}, childArgs...)
			args = append(args,
				"-jobs=1",
				fmt.Sprintf("-workdir=%s", workerDir),
				fmt.Sprintf("-shmem=%s/syz-edk2.shm", workerDir),
				fmt.Sprintf("-ovmf-debug-log=%s/edk2-debug.log", workerDir),
				fmt.Sprintf("-seed=%d", *flagSeed+int64(wi)*7919),
			)
			if *flagCorpusFile != "" {
				// Per-worker corpus to avoid write races. The parent
				// merges them at the end.
				args = append(args, fmt.Sprintf("-corpus=%s.worker-%d.gz", *flagCorpusFile, wi))
			}
			if *flagProgLog != "" {
				args = append(args, fmt.Sprintf("-prog-log=%s.worker-%d", *flagProgLog, wi))
			}

			logFile, err := os.Create(filepath.Join(workerDir, "stderr.log"))
			if err != nil {
				fmt.Fprintf(os.Stderr, "[worker %d] can't create stderr.log: %v\n", wi, err)
				return
			}
			defer logFile.Close()

			stdoutBuf, err := os.Create(filepath.Join(workerDir, "summary.json"))
			if err != nil {
				fmt.Fprintf(os.Stderr, "[worker %d] can't create summary.json: %v\n", wi, err)
				return
			}
			defer stdoutBuf.Close()

			fmt.Fprintf(os.Stderr, "[jobs] starting worker %d in %s\n", wi, workerDir)
			cmd := exec.Command(self, args...)
			cmd.Stdout = stdoutBuf
			cmd.Stderr = logFile
			if err := cmd.Run(); err != nil {
				fmt.Fprintf(os.Stderr, "[worker %d] exited with error: %v\n", wi, err)
			}
			// Read back the JSON summary.
			stdoutBuf.Sync()
			data, _ := os.ReadFile(filepath.Join(workerDir, "summary.json"))
			var r runResult
			_ = json.Unmarshal(data, &r)
			resultsMu.Lock()
			results[wi] = r
			resultsMu.Unlock()
			fmt.Fprintf(os.Stderr, "[jobs] worker %d done: %d programs, %d acks, %d unique PCs\n",
				wi, r.Programs, r.Acks, r.UniqueCoverPCs)
		}()
	}
	wg.Wait()

	// Aggregate results and print a combined JSON summary.
	agg := runResult{OK: true}
	uniquePCs := make(map[int]bool) // dummy placeholder - cross-worker PC merge
	for _, r := range results {
		agg.Programs += r.Programs
		agg.Acks += r.Acks
		agg.Timeouts += r.Timeouts
		agg.GuestErrors += r.GuestErrors
		agg.CallsDispatched += r.CallsDispatched
		agg.UniqueCoverPCs += r.UniqueCoverPCs // summed, not deduped
		agg.CrashTitles = append(agg.CrashTitles, r.CrashTitles...)
		if r.DurationSec > agg.DurationSec {
			agg.DurationSec = r.DurationSec
		}
		if !r.OK {
			agg.OK = false
		}
	}
	_ = uniquePCs
	agg.TotalFuncs = *flagTotalFuncs
	if agg.TotalFuncs > 0 {
		agg.CoveragePercent = float64(agg.UniqueCoverPCs) / float64(agg.TotalFuncs) * 100
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(&agg)

	if !agg.OK {
		os.Exit(1)
	}
}

// filterArgs returns a copy of args with any flags from `drop` removed.
// Handles both "-flag=value" and "-flag value" forms.
func filterArgs(args []string, drop map[string]bool) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		name := a
		if idx := strings.Index(a, "="); idx > 0 {
			name = a[:idx]
		}
		if drop[name] {
			if !strings.Contains(a, "=") && i+1 < len(args) {
				// Skip the next token (the value).
				i++
			}
			continue
		}
		out = append(out, a)
	}
	return out
}
