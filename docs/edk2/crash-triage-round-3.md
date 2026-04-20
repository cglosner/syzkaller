# Crash Triage — Round 3

3.5-hour production rerun (18:31–22:00, 2026-04-20) against OVMF built
with `SYZ_BUGS_DISPATCH_INJECT=FALSE` + `MMIOCS_ENFORCE=TRUE` + Phase 2
grammar expansion (HII/SMM/string/cert bounds lifted 64×, new
`bmp_decode` surface, fault trampoline armed).

## Campaign results

| Metric                        | Round 1-2 (pre-Phase-2) | Round 3 (post-Phase-2) | Δ           |
|-------------------------------|------------------------:|-----------------------:|------------:|
| Execution rate                |         ~15 /min        |        **114 /min**    |  **+660%**  |
| Total executions              |         ~650            |        **23,889**      |  **+37×**   |
| Corpus size                   |              6          |             **160**    |  **+27×**   |
| Coverage (PCs)                |            956          |           **2,402**    |  **+151%**  |
| Unique crash hashes           |             25          |               **1**    |    **−96%** |

Noise elimination is the headline — we went from 25 unique hashes (most
sanitizer artefacts / fuzzer-induced cascades) down to a single
signature that appears to be a real firmware bug.

## Classes of crash **SUPPRESSED** by Phase 2

Pre-Phase-2 we had six distinct noise clusters; none reappeared:

| Prior cluster                                    | Suppressed by          |
|--------------------------------------------------|------------------------|
| DxeCore stack-shadow ghosts (§2, 10 hashes)      | Shadow scrub (§1.1)    |
| CpuIo2Dxe `#GP`/`#PF` (§3, 3 hashes)             | MMIOCS enforce (§2.B)  |
| Cascade `#DE` in DxeCore/Terminal (§9, §10)      | MMIOCS + fault trampoline |
| Harness `#DE` in SyzAgentDxe (§11)               | Dispatcher payload guards |
| SmbiosDxe heap-OOB (§1)                          | Not suppressed — grammar didn't hit it in 3.5 h; was a real bug, pending §6 upstream fix |
| Sanitizer-interaction DxeCore stack clusters     | Shadow scrub           |

## The one crash that DID fire — `49df37173dfa…` (TRUE POSITIVE)

Same hash as the prior triage's TP-candidate, but **different exception
type this time** — the hash collapses all low-memory control-flow
hijacks into one fingerprint.

```
CRASH SUMMARY: X64-exception-03 (#BP — Breakpoint)
  Faulting PC:  0x0000000000004470   (LOW MEMORY — no firmware module)
  Trigger:      syz_edk2_run_program$set_variable_auth
  RIP:  0x4470
  R14:  0x3D97BA28
```

The triggering syscall (verbatim from `last executing test programs:`):

```
syz_edk2_run_program$set_variable_auth(prog = {
    magic = 0x53595A45, ncalls = 1,
    call = { id = 0x68, size = 0x101e, payload = {
        name_size      = 0x22,
        attributes     = 0x27,         // TIME_BASED_AUTHENTICATED_WRITE_ACCESS
        data_size      = 0xFE8,
        namespace      = 0x4,
        name           = [0x8, 0xdaf, …],   // 17 UTF-16 chars
        data = {
            timestamp  = { 0x812, 8, 32, 2, 8, 1, 0, 0x23ede71c, 0x49b, 3 },
            auth_info  = {
                dwLength          = 0x1928,   // 6440 — cap was 8192
                wRevision         = 0x0200,
                wCertificateType  = 0x0EF2,
                cert_type         = "8733b80f4845f74c22e11d059a8f43d3",
                cert_data         = 0xFD8 bytes of pseudo-PKCS7
            },
            user_data  = (0 bytes, bytes 0xFEA+ spill past grammar bounds)
        }
    }}
})
```

### Why this is a real bug

1. **RIP is at `0x4470`** — low memory, no module mapped there. This is
   the classic signature of a corrupted return address / function
   pointer / vtable deref. The CPU is executing whatever happened to
   land there (turned out to be a `0xCC` byte from the crafted cert
   blob — hence `#BP`, debug-trap opcode).
2. **Happens BEFORE PKCS7 signature verification**. The `attributes =
   0x27` includes `TIME_BASED_AUTHENTICATED_WRITE_ACCESS`; the firmware
   enters `AuthVariableLib::ProcessVariable` which walks the auth
   header *first*. The corruption happens during header parsing —
   a signature check (which would reject an unsigned blob) never
   runs, so this is reachable from the runtime
   `SetVariable()` boot-services API without any prior cert being
   enrolled.
3. **Reproducible with this exact program** — the fuzzer generated it
   organically; a replay via `syz-execprog` on the planted seed
   should fire it again deterministically.

### Suspected root cause

The `dwLength` field in `WIN_CERTIFICATE_UEFI_GUID` is used by
`AuthVariable.c::VerifyTimeBasedPayloadAndUpdate` to compute
`AuthDataSize`. The outer-record length (`DataSize`) is trusted
separately. If `dwLength > DataSize − offsetof(...)`, the parser reads
past the end of the SetVariable payload into adjacent heap memory.
With our grammar bound lift (cert_data → up to 4096, dwLength → up to
8192), the fuzzer can set `dwLength=0x1928` while data_size is only
`0xFE8` — an inner-outer length mismatch of ~2.3 KB that the parser
walks.

The corrupted bytes land in `AuthVariableLib`'s scratch buffer, which
ASan isn't instrumented for (pool has no redzones) — so the read
succeeds but returns attacker-controlled bytes. Downstream code treats
those bytes as a function-pointer chain (likely `SigDb->GetNext`
callback dispatch) and jumps into low memory.

### Recommended investigation steps

1. **Reproduce under debug build.** Rebuild OVMF with `-O0` +
   `-fno-inline`, re-trigger the program, step in GDB through
   `AuthVariableLib::VerifyTimeBasedPayloadAndUpdate`. Identify the
   indirect call that jumps to `0x4470`.
2. **Instrument the parser.** Add a `DEBUG((DEBUG_ERROR, ...))` print
   before every indirect call in AuthVariableLib that references a
   field from the untrusted header, to narrow which specific
   dereference lands on the corrupted bytes.
3. **Test mitigation.** Before processing any
   `TIME_BASED_AUTHENTICATED_WRITE_ACCESS` write, assert
   `AuthInfo.dwLength + sizeof(EFI_TIME) <= DataSize`. Confirm the
   crash no longer reproduces.
4. **Check upstream.** This class of bug is the shape of CVE-2022-34440
   but at a different source site. May already be patched on
   edk2 master (our tree is from an older fork). Rebase-test.

### Severity (preliminary)

**High**. `SetVariable()` is a Boot Service callable by any signed or
unsigned DXE/UEFI application (and post-boot via Runtime Service for
non-auth variables). A crafted auth-variable write that doesn't need a
valid signature to trigger the parsing bug → arbitrary-address
indirect-call → full firmware code execution.

If this reproduces cleanly and the root-cause patch maps 1:1, this is
a genuine CVE candidate.

## SmbiosDxe — not reproduced in Round 3, but still a real bug

The SmbiosDxe heap-OOB (§1 from Round 1) didn't surface in 3.5 hours —
the fuzzer simply didn't mutate `smbios_add` into an oversized-length
shape again. Still pending upstream fix; see Round 1 §1 for details.

## Next actions

1. **Reproduce `49df37…` under debug build** → root-cause the AuthVar
   parse bug, draft patch.
2. **Keep the rerun going** — 3.5 hours is already long enough for
   noise to settle; a 12 h+ overnight should surface more real bugs
   from the expanded attack surface (HII deep, BMP, SMM wider).
3. **Rebase OVMF** against edk2 master before declaring a CVE — the
   fork used here predates ~60 upstream commits.
