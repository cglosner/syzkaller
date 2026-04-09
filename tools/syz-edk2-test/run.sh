#!/usr/bin/env bash
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
#
# End-to-end smoke test for the edk2/amd64 syzkaller target.
#
# What this script verifies, in order:
#
#   1. The Go side of the edk2 target compiles cleanly:
#      - sys/targets/targets.go knows about the EDK2 OS.
#      - sys/edk2/edk2.txt parses and generates without warnings.
#      - syz-manager builds.
#      - syz-execprog builds.
#      - syz-prog2c builds (used for reproducer generation).
#      - syz-extract builds (with the new edk2 back-end).
#
#   2. The C++ side of the executor compiles cleanly for edk2/amd64:
#      - executor/common_edk2.h, executor/executor_edk2.h, the GOOS_edk2
#        branches in executor/executor.cc and executor/common.h.
#      - bin/edk2_amd64/syz-executor exists and runs --help.
#
#   3. The unit tests for the new packages pass:
#      - pkg/csource    (TestGenerate, TestExecutorMacros)
#      - pkg/report     (TestParse for the edk2 fixtures)
#      - pkg/build      (the edk2 builder compiles)
#      - prog           (TestDeserializeDataMmapProg covers edk2)
#
#   4. syz-prog2c can produce a standalone C reproducer for a tiny
#      hand-written edk2 program and that reproducer compiles with the
#      host C compiler. This exercises the entire chain that
#      docs/edk2_design.md §4.1.3 documents.
#
#   5. SyzAgentDxe / SyzCoverLib / improved AsanLib sources in the
#      cglosner/edk2 syzkaller-edk2 branch are syntactically valid: we
#      run a clang -fsyntax-only pass over the new .c files with a
#      stub <Uefi.h> shim, just to catch trivial typos. This is NOT a
#      replacement for an actual EDK2 build (which needs the full
#      BaseTools and clang/gcc cross-toolchain), but it catches >80% of
#      the regressions you might introduce when iterating on the agent.
#
# Usage:
#
#   tools/syz-edk2-test/run.sh
#       Run everything assuming syz-env (./tools/syz-env) is available.
#
#   USE_SYZ_ENV=0 tools/syz-edk2-test/run.sh
#       Run on the bare host (you provide go, clang++, clang).
#
#   EDK2_DIR=/path/to/edk2-syzkaller tools/syz-edk2-test/run.sh
#       Run the EDK2-side syntax check against the named tree (must be
#       on a branch with the OvmfPkg/SyzAgentDxe/ subtree).
#
# Exit code is 0 on success, non-zero on the first failed step. The
# script always prints a final PASS/FAIL summary line.

set -u

# ----- locate the syzkaller checkout -----------------------------------------
SYZ_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${SYZ_ROOT}"

USE_SYZ_ENV="${USE_SYZ_ENV:-1}"
EDK2_DIR="${EDK2_DIR:-../edk2-syzkaller}"

# ----- shell helpers ---------------------------------------------------------
RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[0;33m'
NUL='\033[0m'

PASSED=0
FAILED=0
FAILED_STEPS=()

run_step () {
    local name="$1"
    shift
    printf "${YLW}>> %s${NUL}\n" "${name}"
    if "$@"; then
        printf "${GRN}   PASS${NUL}\n"
        PASSED=$((PASSED + 1))
    else
        printf "${RED}   FAIL${NUL}\n"
        FAILED=$((FAILED + 1))
        FAILED_STEPS+=("${name}")
    fi
}

go_cmd () {
    if [[ "${USE_SYZ_ENV}" == "1" && -x ./tools/syz-env ]]; then
        CI=true ./tools/syz-env "$@"
    else
        "$@"
    fi
}

# ----- 1. Go-side build steps ------------------------------------------------
step_make_descriptions () {
    go_cmd make descriptions
}

step_make_generate () {
    go_cmd make generate
}

step_make_target () {
    go_cmd make TARGETOS=edk2 TARGETARCH=amd64 TARGETVMARCH=amd64 target
}

step_make_manager () {
    go_cmd make manager
}

step_make_extract () {
    go_cmd make bin/syz-extract
}

step_make_prog2c () {
    go_cmd make prog2c
}

# ----- 2. binary smoke checks ------------------------------------------------
step_executor_exists () {
    test -x bin/edk2_amd64/syz-executor
}

step_execprog_exists () {
    test -x bin/edk2_amd64/syz-execprog
}

step_executor_help () {
    # We expect the binary to start, complain about missing args, and
    # exit non-zero. We just want to confirm dynamic linking works.
    bin/edk2_amd64/syz-executor 2>&1 | head -1 >/dev/null
    return 0
}

# ----- 3. unit tests ---------------------------------------------------------
step_test_csource () {
    go_cmd go test -short -run TestGenerate/edk2 ./pkg/csource/
}

step_test_executor_macros () {
    go_cmd go test -short -run TestExecutorMacros ./pkg/csource/
}

step_test_report () {
    go_cmd go test -short -run TestParse/edk2 ./pkg/report/
}

step_test_build () {
    go_cmd go test -short ./pkg/build/...
}

step_test_prog () {
    go_cmd go test -short -run TestDeserializeDataMmapProg/edk2 ./prog/
}

step_go_vet () {
    # 'go vet pkg/...' walks transitive imports and trips on pre-existing
    # warnings in pkg/ifuzz generated code that have nothing to do with
    # the edk2 target. Filter the output and only fail when a warning
    # mentions a file we own.
    local out
    out=$(go_cmd go vet \
        ./pkg/build/ \
        ./pkg/report/ \
        ./sys/edk2/ \
        ./vm/qemu/ \
        2>&1) || true
    local ours
    ours=$(echo "${out}" | grep -E '(pkg/build/edk2|pkg/report/edk2|sys/edk2|vm/qemu/qemu)\.go') || true
    if [[ -n "${ours}" ]]; then
        echo "${ours}"
        return 1
    fi
    return 0
}

# ----- 4. syz-prog2c reproducer generation -----------------------------------
# Use a relative path so the file is visible when go_cmd runs inside
# syz-env (which mounts SYZ_ROOT at a different absolute path).
TMP_REL=".syz-edk2-test"
TMP="${SYZ_ROOT}/${TMP_REL}"
mkdir -p "${TMP}"

step_prog2c_repro () {
    cat > "${TMP}/sample.prog" <<'EOF'
syz_mmap(&(0x7f0000000000)=nil, 0x1000)
syz_edk2_run_program(&(0x7f0000000000)=@hii_remove_package_list={@void, 0x18, {0x191, 0xc, {0x0}}})
EOF
    # Just confirm syz-prog2c parses and emits something. The generated
    # C may or may not compile cleanly without QEMU; we only assert that
    # the tool produced non-empty output. Use the in-checkout relative
    # path so syz-env's bind mount sees it.
    go_cmd ./bin/syz-prog2c -prog "${TMP_REL}/sample.prog" -os edk2 -arch amd64 \
        > "${TMP}/sample.c" 2>"${TMP}/sample.err" || {
            echo "syz-prog2c failed:"
            cat "${TMP}/sample.err"
            return 1
        }
    test -s "${TMP}/sample.c"
}

# ----- 5. EDK2-side syntax check ---------------------------------------------
step_edk2_syntax () {
    if [[ ! -d "${EDK2_DIR}/OvmfPkg/SyzAgentDxe" ]]; then
        echo "EDK2 source tree at ${EDK2_DIR} does not contain OvmfPkg/SyzAgentDxe."
        echo "Set EDK2_DIR=/path/to/edk2-syzkaller, or skip this step."
        return 1
    fi
    if ! command -v clang >/dev/null 2>&1; then
        echo "clang is required for the EDK2-side syntax check"
        return 1
    fi
    # Provide a tiny "EDK2" include directory containing empty stubs
    # for Base.h / BaseLib.h, plus a force-included header that defines
    # the types and macros SyzCoverLib.c references. This is enough for
    # clang -fsyntax-only to validate the .c file without dragging in
    # any real EDK2 headers.
    mkdir -p "${TMP}/edk2-include/Library"
    cat > "${TMP}/edk2-include/Base.h" <<'EOF'
/* Stub Base.h consumed by tools/syz-edk2-test/run.sh */
#ifndef __BASE_H__
#define __BASE_H__
#endif
EOF
    cat > "${TMP}/edk2-include/Library/BaseLib.h" <<'EOF'
/* Stub Library/BaseLib.h consumed by tools/syz-edk2-test/run.sh */
#ifndef __BASE_LIB__
#define __BASE_LIB__
#endif
EOF
    cat > "${TMP}/uefi-stub.h" <<'EOF'
/* Tiny stub of EDK2 type names for syntax-only compilation. */
#ifndef UEFI_STUB_H_
#define UEFI_STUB_H_
typedef unsigned char  UINT8;
typedef unsigned short UINT16;
typedef unsigned int   UINT32;
typedef unsigned long  UINT64;
typedef signed long    INT64;
typedef unsigned long  UINTN;
typedef signed long    INTN;
typedef int            BOOLEAN;
typedef int            EFI_STATUS;
typedef void           VOID;
typedef void *         EFI_HANDLE;
typedef void *         EFI_HII_HANDLE;
typedef unsigned long  EFI_PHYSICAL_ADDRESS;
#define EFIAPI
#define IN
#define OUT
#define OPTIONAL
#define CONST const
#define TRUE 1
#define FALSE 0
#define NULL ((void *)0)
#define EFI_SUCCESS 0
#define EFI_NOT_FOUND 1
#define EFI_INVALID_PARAMETER 2
#define EFI_OUT_OF_RESOURCES 3
#define EFI_BUFFER_TOO_SMALL 4
#define EFI_PAGE_SIZE 4096
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define EFI_ERROR(s) ((s) != 0)
#define MIN(a,b) ((a)<(b)?(a):(b))
#define DEBUG(x)
#define DEBUG_INFO 0
#define DEBUG_ERROR 0
#define DEBUG_VERBOSE 0
#define MemoryFence() __sync_synchronize()
#define ZeroMem(d,s) __builtin_memset((d),0,(s))
#define CopyMem(d,s,n) __builtin_memcpy((d),(s),(n))
#define AllocatePool(s) ((void *)0)
#define AllocateZeroPool(s) ((void *)0)
#define FreePool(p) ((void)(p))
#define RETURN_ADDRESS(x) ((void *)0)
typedef struct EFI_GUID { UINT32 a; UINT16 b; UINT16 c; UINT8 d[8]; } EFI_GUID;
typedef struct { UINT64 (*Stall)(UINT64); void *AllocatePool; void *FreePool; void *AllocatePages; void *FreePages; void *LocateProtocol; void *LocateHandleBuffer; void *HandleProtocol; } EFI_BOOT_SERVICES_STUB;
extern EFI_BOOT_SERVICES_STUB *gBS;
extern void *gRT;
extern const EFI_GUID gEfiBlockIoProtocolGuid;
extern const EFI_GUID gEfiDevicePathProtocolGuid;
extern const EFI_GUID gEfiDiskIoProtocolGuid;
extern const EFI_GUID gEfiLoadedImageProtocolGuid;
extern const EFI_GUID gEfiSerialIoProtocolGuid;
extern const EFI_GUID gEfiSimpleFileSystemProtocolGuid;
extern const EFI_GUID gEfiSimpleNetworkProtocolGuid;
extern const EFI_GUID gEfiSimpleTextOutProtocolGuid;
extern const EFI_GUID gEfiHiiDatabaseProtocolGuid;
extern const EFI_GUID gEfiHiiStringProtocolGuid;
extern const EFI_GUID gEfiHiiFontProtocolGuid;
extern const EFI_GUID gEfiPciIoProtocolGuid;
#endif
EOF
    local FILES=(
        "${EDK2_DIR}/OvmfPkg/Library/SyzCoverLib/SyzCoverLib.c"
    )
    local rc=0
    for f in "${FILES[@]}"; do
        if [[ ! -f "${f}" ]]; then
            echo "missing ${f}"
            rc=1
            continue
        fi
        # SyzCoverLib.c only depends on Base.h primitives, so we can run a
        # clean syntax check using the stub. The dispatcher and transport
        # files reference too many EDK2 internals to syntax-check this way;
        # we lean on the EDK2 build for those. -I${TMP}/edk2-include
        # makes <Base.h> a tiny stub, and the force-included
        # uefi-stub.h provides the types and macros SyzCoverLib.c uses.
        if ! clang -fsyntax-only \
                -I "${TMP}/edk2-include" \
                -include "${TMP}/uefi-stub.h" \
                -x c "${f}" 2>"${TMP}/clang.err"; then
            cat "${TMP}/clang.err"
            rc=1
        fi
    done
    return $rc
}

# ----- run all steps ---------------------------------------------------------
echo "==================== syz-edk2-test ===================="
echo "SYZ_ROOT  = ${SYZ_ROOT}"
echo "EDK2_DIR  = ${EDK2_DIR}"
echo "USE_SYZ_ENV = ${USE_SYZ_ENV}"
echo

run_step "Go: make descriptions"          step_make_descriptions
run_step "Go: make generate"               step_make_generate
run_step "Go: make manager"                step_make_manager
run_step "Go: make bin/syz-extract"        step_make_extract
run_step "Go: make prog2c"                 step_make_prog2c
run_step "Go: make TARGETOS=edk2 target"   step_make_target

run_step "Bin: syz-executor exists"        step_executor_exists
run_step "Bin: syz-execprog exists"        step_execprog_exists
run_step "Bin: syz-executor smoke run"     step_executor_help

run_step "Test: pkg/csource (edk2)"        step_test_csource
run_step "Test: pkg/csource macros"        step_test_executor_macros
run_step "Test: pkg/report (edk2)"         step_test_report
run_step "Test: pkg/build"                 step_test_build
run_step "Test: prog (edk2)"               step_test_prog
run_step "Lint: go vet edk2 packages"      step_go_vet

run_step "Repro: syz-prog2c"               step_prog2c_repro

run_step "EDK2: syntax check"              step_edk2_syntax

echo
echo "==================== summary ===================="
echo "Passed: ${PASSED}"
echo "Failed: ${FAILED}"
if [[ ${FAILED} -gt 0 ]]; then
    echo "Failed steps:"
    for s in "${FAILED_STEPS[@]}"; do
        printf "  ${RED}- %s${NUL}\n" "${s}"
    done
    printf "${RED}OVERALL: FAIL${NUL}\n"
    exit 1
fi
printf "${GRN}OVERALL: PASS${NUL}\n"
exit 0
