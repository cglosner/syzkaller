#!/usr/bin/env bash
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
#
# End-to-end build + fuzz runner for the edk2/amd64 target.
#
# What this script does:
#
#   1. Clones (if missing) the cglosner/edk2 syzkaller-edk2 branch and
#      the cglosner/qemu firmware-fuzz-coverage branch.
#   2. Builds EDK2 BaseTools, then OvmfPkgX64 with SYZ_AGENT_ENABLE=TRUE
#      and ASAN_ENABLE=TRUE.
#   3. Builds the syzkaller side: manager, executor, and the standalone
#      syz-edk2-fuzz driver in this directory.
#   4. Boots OVMF in stock qemu-system-x86_64 with an ivshmem-plain
#      device wired to a host file, runs a short fuzzing campaign via
#      syz-edk2-fuzz, and prints the JSON summary.
#   5. If the campaign reports zero acks (snapshot/transport broken),
#      builds the modified cglosner/qemu and retries with that binary.
#
# Run from a syzkaller checkout. Adjust paths via env vars below.

set -u

# ----- locate / configure ----------------------------------------------------
SYZ_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EDK2_DIR="${EDK2_DIR:-/home/gl055/research/projects/edk2-syzkaller}"
QEMU_DIR="${QEMU_DIR:-/home/gl055/research/projects/qemu-fwfuzz}"
QEMU_BIN_DEFAULT="${QEMU_BIN_DEFAULT:-qemu-system-x86_64}"
QEMU_BIN_FALLBACK="${QEMU_BIN_FALLBACK:-${QEMU_DIR}/build/qemu-system-x86_64}"
WORKDIR="${WORKDIR:-${SYZ_ROOT}/.syz-edk2-fuzz}"
DURATION="${DURATION:-30s}"
SEED="${SEED:-1}"
SKIP_BUILD="${SKIP_BUILD:-0}"
USE_SYZ_ENV="${USE_SYZ_ENV:-1}"
ASAN_INSTRUMENT="${ASAN_INSTRUMENT:-FALSE}"
UBSAN_INSTRUMENT="${UBSAN_INSTRUMENT:-FALSE}"
SNAPSHOT_EVERY="${SNAPSHOT_EVERY:-0}"
CALL_SET="${CALL_SET:-all}"
USE_GRAMMAR="${USE_GRAMMAR:-1}"
# Default grammar-skip excludes the HII variants because the agent
# forwards raw fuzzer bytes to Hii->NewPackageList, which wedges on
# malformed package headers. Override with GRAMMAR_SKIP="" to enable.
GRAMMAR_SKIP="${GRAMMAR_SKIP:-400,401}"

mkdir -p "${WORKDIR}"

GRN='\033[0;32m'
RED='\033[0;31m'
YLW='\033[0;33m'
NUL='\033[0m'

step() { printf "${YLW}== %s ==${NUL}\n" "$*"; }
ok()   { printf "${GRN}OK:${NUL}   %s\n" "$*"; }
warn() { printf "${RED}WARN:${NUL} %s\n" "$*"; }
die()  { printf "${RED}FATAL:${NUL} %s\n" "$*" >&2; exit 1; }

go_cmd() {
    if [[ "${USE_SYZ_ENV}" == "1" && -x "${SYZ_ROOT}/tools/syz-env" ]]; then
        ( cd "${SYZ_ROOT}" && CI=true ./tools/syz-env "$@" )
    else
        ( cd "${SYZ_ROOT}" && "$@" )
    fi
}

# ----- 1. Pull repos ---------------------------------------------------------
step "fetching dependencies"
if [[ ! -d "${EDK2_DIR}" ]]; then
    git clone https://github.com/cglosner/edk2.git "${EDK2_DIR}" \
        || die "edk2 clone failed"
    ( cd "${EDK2_DIR}" && git checkout syzkaller-edk2 2>/dev/null \
        || git checkout simics-sanitizer )
    ok "edk2 checked out at ${EDK2_DIR}"
fi
if [[ ! -d "${EDK2_DIR}/MdeModulePkg/Library/BrotliCustomDecompressLib/brotli/c/include" ]]; then
    ( cd "${EDK2_DIR}" && git submodule update --init --recursive ) \
        || die "edk2 submodule update failed"
fi

if [[ ! -d "${QEMU_DIR}" ]]; then
    git clone --depth=1 -b dev/firmware-fuzz-coverage \
        https://github.com/cglosner/qemu.git "${QEMU_DIR}" \
        || warn "qemu clone failed (will skip fallback path)"
fi

# ----- 2. Build EDK2 ---------------------------------------------------------
if [[ "${SKIP_BUILD}" == "0" ]]; then
    step "building EDK2 BaseTools"
    ( cd "${EDK2_DIR}" && make -C BaseTools -j"$(nproc)" >/dev/null 2>&1 ) \
        || die "BaseTools build failed"

    step "building OVMF with SYZ_AGENT_ENABLE=TRUE ASAN_INSTRUMENT=${ASAN_INSTRUMENT} UBSAN_INSTRUMENT=${UBSAN_INSTRUMENT}"
    extra_build_args=""
    extra_env=""
    if [[ "${ASAN_INSTRUMENT:-FALSE}" == "TRUE" || "${UBSAN_INSTRUMENT:-FALSE}" == "TRUE" ]]; then
        # Instrumented builds bust the default 4 MiB FVMAIN_COMPACT.
        extra_build_args="-D FD_SIZE_IN_KB=8192"
        # The gcc-kasan-wrapper strips -fasan-shadow-offset from the
        # command line when -fno-sanitize=kernel-address is also present
        # (needed for per-component carve-outs like SyzAgentDxe).
        extra_env="GCC5_BIN=${EDK2_DIR}/BaseTools/BinWrappers/PosixLike/gcc-wrap/"
    fi
    ( cd "${EDK2_DIR}" && bash -c '
        export '"${extra_env}"'
        . ./edksetup.sh >/dev/null
        build -p OvmfPkg/OvmfPkgX64.dsc -a X64 -t GCC5 -b NOOPT \
            -D SYZ_AGENT_ENABLE=TRUE -D ASAN_ENABLE=TRUE \
            -D ASAN_INSTRUMENT='"${ASAN_INSTRUMENT:-FALSE}"' \
            -D UBSAN_INSTRUMENT='"${UBSAN_INSTRUMENT:-FALSE}"' \
            '"${extra_build_args}"' -n '"$(nproc)" ) \
        > "${WORKDIR}/edk2-build.log" 2>&1 \
        || { tail -30 "${WORKDIR}/edk2-build.log"; die "OVMF build failed"; }
    ok "OVMF built (log: ${WORKDIR}/edk2-build.log)"
fi

OVMF_FV="${EDK2_DIR}/Build/OvmfX64/NOOPT_GCC5/FV"
[[ -f "${OVMF_FV}/OVMF_CODE.fd" ]] || die "no OVMF_CODE.fd at ${OVMF_FV}"
[[ -f "${OVMF_FV}/OVMF_VARS.fd" ]] || die "no OVMF_VARS.fd at ${OVMF_FV}"

# ----- 3. Build syzkaller ----------------------------------------------------
if [[ "${SKIP_BUILD}" == "0" ]]; then
    step "building syzkaller (manager, edk2 target, syz-edk2-fuzz)"
    go_cmd make manager >/dev/null \
        || die "syz-manager build failed"
    go_cmd make TARGETOS=edk2 TARGETARCH=amd64 TARGETVMARCH=amd64 target >/dev/null \
        || die "edk2 target build failed"
    go_cmd go build -o bin/syz-edk2-fuzz ./tools/syz-edk2-fuzz/ \
        || die "syz-edk2-fuzz build failed"
    ok "syzkaller built"
fi

# ----- 4. Run fuzzing campaign with stock qemu -------------------------------
step "running fuzzing campaign (stock qemu, duration=${DURATION})"
SHMEM="${WORKDIR}/syz-edk2.shm"
DEBUG_LOG="${WORKDIR}/edk2-debug.log"
SUMMARY="${WORKDIR}/summary.json"

run_fuzz() {
    local qemu_bin="$1"
    rm -f "${SHMEM}" "${DEBUG_LOG}"
    local extra=()
    if [[ "${USE_GRAMMAR}" == "1" ]]; then
        extra+=(-use-grammar)
        if [[ -n "${GRAMMAR_SKIP}" ]]; then
            extra+=(-grammar-skip "${GRAMMAR_SKIP}")
        fi
    fi
    "${SYZ_ROOT}/bin/syz-edk2-fuzz" \
        -ovmf-code "${OVMF_FV}/OVMF_CODE.fd" \
        -ovmf-vars "${OVMF_FV}/OVMF_VARS.fd" \
        -ovmf-debug-log "${DEBUG_LOG}" \
        -shmem "${SHMEM}" \
        -workdir "${WORKDIR}" \
        -qemu "${qemu_bin}" \
        -duration "${DURATION}" \
        -seed "${SEED}" \
        -snapshot-every "${SNAPSHOT_EVERY}" \
        -call-set "${CALL_SET}" \
        -prog-log "${WORKDIR}/programs.log" \
        -syz-prog \
        "${extra[@]}" \
        > "${SUMMARY}" 2> "${WORKDIR}/fuzz-stderr.log"
}

set +e
run_fuzz "${QEMU_BIN_DEFAULT}"
RC=$?
set -e

cat "${SUMMARY}"
echo "--- last 20 lines of OVMF debug log:"
tail -20 "${DEBUG_LOG}" 2>&1 || true

# Pull a couple of headline numbers out of the JSON for the wrap-up.
acks=$(grep '"acks"' "${SUMMARY}" 2>/dev/null | head -1 | grep -oE '[0-9]+' | head -1 || echo 0)
progs=$(grep '"programs"' "${SUMMARY}" 2>/dev/null | head -1 | grep -oE '[0-9]+' | head -1 || echo 0)
covpcs=$(grep '"unique_cover_pcs"' "${SUMMARY}" 2>/dev/null | head -1 | grep -oE '[0-9]+' | head -1 || echo 0)

if [[ "${RC}" == "0" && "${acks}" -gt 0 ]]; then
    ok "campaign success: ${progs} programs, ${acks} acks, ${covpcs} unique cover PCs"
    exit 0
fi

# ----- 5. Fall back to modified QEMU if available ----------------------------
warn "stock qemu campaign failed (rc=${RC}, acks=${acks}); trying modified QEMU"
if [[ ! -x "${QEMU_BIN_FALLBACK}" ]]; then
    if [[ -d "${QEMU_DIR}" ]]; then
        step "building cglosner/qemu firmware-fuzz-coverage branch"
        ( cd "${QEMU_DIR}" \
            && ./configure --target-list=x86_64-softmmu --disable-werror \
                          --disable-docs --disable-tools --disable-gtk \
                          --disable-vnc --enable-kvm \
            && make -j"$(nproc)" qemu-system-x86_64 ) \
            > "${WORKDIR}/qemu-build.log" 2>&1 \
            || { tail -30 "${WORKDIR}/qemu-build.log"; die "modified qemu build failed"; }
    else
        die "modified qemu source tree not present at ${QEMU_DIR}"
    fi
fi
[[ -x "${QEMU_BIN_FALLBACK}" ]] || die "no ${QEMU_BIN_FALLBACK} after build"

step "running fuzzing campaign (modified qemu)"
set +e
run_fuzz "${QEMU_BIN_FALLBACK}"
RC=$?
set -e
cat "${SUMMARY}"
echo "--- last 20 lines of OVMF debug log:"
tail -20 "${DEBUG_LOG}" 2>&1 || true

acks=$(grep '"acks"' "${SUMMARY}" 2>/dev/null | head -1 | grep -oE '[0-9]+' | head -1 || echo 0)
progs=$(grep '"programs"' "${SUMMARY}" 2>/dev/null | head -1 | grep -oE '[0-9]+' | head -1 || echo 0)
covpcs=$(grep '"unique_cover_pcs"' "${SUMMARY}" 2>/dev/null | head -1 | grep -oE '[0-9]+' | head -1 || echo 0)

if [[ "${RC}" == "0" && "${acks}" -gt 0 ]]; then
    ok "modified-qemu campaign success: ${progs} programs, ${acks} acks, ${covpcs} unique cover PCs"
    exit 0
fi

die "both campaigns failed (rc=${RC})"
