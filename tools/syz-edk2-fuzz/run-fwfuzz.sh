#!/usr/bin/env bash
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
#
# Wrapper for cglosner/qemu-fwfuzz snapshot fuzzing of OVMF.
#
# The standalone syz-edk2-fuzz driver uses KVM with cold-restart on
# every wedge, which limits throughput. qemu-fwfuzz is a TCG-based
# fuzzer that snapshots CPU+memory at a trigger PC and restores for
# each iteration — no boot overhead between iterations. The trigger
# is SyzFwfuzzTrigger() in our SyzAgentDxe driver, which dispatches
# whatever bytes the host wrote into gSyzFwfuzzInputBuffer.
#
# This script:
#   1. Boots OVMF once in TCG mode to capture the runtime addresses
#      of trigger and input buffer (printed by SyzAgentDxe debug log)
#   2. Launches fwfuzz.py with those addresses
#
# Usage: ./run-fwfuzz.sh [duration_minutes]

set -u
MINUTES="${1:-10}"

SYZ_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EDK2_DIR="${EDK2_DIR:-/home/gl055/research/projects/edk2-syzkaller}"
QEMU_DIR="${QEMU_DIR:-/home/gl055/research/projects/qemu-fwfuzz}"
# The fuzzing build (with plugins next to it) lives in build-fwfuzz/.
QEMU_BUILD="${QEMU_BUILD:-${QEMU_DIR}/build-fwfuzz}"
QEMU_BIN="${QEMU_BIN:-${QEMU_BUILD}/qemu-system-x86_64}"
OUTDIR="${OUTDIR:-${SYZ_ROOT}/.syz-edk2-fwfuzz}"

OVMF_CODE="${EDK2_DIR}/Build/OvmfX64/NOOPT_GCC5/FV/OVMF_CODE.fd"
OVMF_VARS="${EDK2_DIR}/Build/OvmfX64/NOOPT_GCC5/FV/OVMF_VARS.fd"

[[ -x "${QEMU_BIN}" ]] || { echo "FATAL: ${QEMU_BIN} not found"; exit 1; }
[[ -f "${OVMF_CODE}" ]] || { echo "FATAL: ${OVMF_CODE} not found"; exit 1; }

mkdir -p "${OUTDIR}"
cp "${OVMF_VARS}" "${OUTDIR}/vars.fd"
truncate -s 256M "${OUTDIR}/shm"

GRN='\033[0;32m'; YLW='\033[0;33m'; RED='\033[0;31m'; NUL='\033[0m'

step() { printf "${YLW}== %s ==${NUL}\n" "$*"; }
ok()   { printf "${GRN}OK:${NUL}   %s\n" "$*"; }
die()  { printf "${RED}FATAL:${NUL} %s\n" "$*" >&2; exit 1; }

# ----- 1. Boot once in TCG to capture trigger/input addresses -------------
step "discovering trigger address (TCG boot, ~60s)"
rm -f "${OUTDIR}/discover.log"
"${QEMU_BIN}" \
    -machine q35,accel=tcg,smm=off \
    -cpu max \
    -m 1024 \
    -nodefaults \
    -no-reboot \
    -nographic \
    -serial null \
    -drive if=pflash,format=raw,readonly=on,file="${OVMF_CODE}" \
    -drive if=pflash,format=raw,file="${OUTDIR}/vars.fd" \
    -debugcon file:"${OUTDIR}/discover.log" \
    -global isa-debugcon.iobase=0x402 \
    -object memory-backend-file,id=syzcov,share=on,mem-path="${OUTDIR}/shm",size=256M \
    -device ivshmem-plain,memdev=syzcov \
    > "${OUTDIR}/discover-qemu.log" 2>&1 &
DISC_PID=$!

for i in $(seq 1 90); do
    if grep -q "SYZFWFUZZ" "${OUTDIR}/discover.log" 2>/dev/null; then
        break
    fi
    sleep 2
done
kill ${DISC_PID} 2>/dev/null
wait 2>/dev/null

LINE=$(grep "SYZFWFUZZ" "${OUTDIR}/discover.log" | head -1)
[[ -n "${LINE}" ]] || die "SYZFWFUZZ marker never appeared. discover.log tail:
$(tail -20 "${OUTDIR}/discover.log")"

TRIGGER=$(echo "${LINE}" | grep -oE 'trigger=0x[0-9a-fA-F]+' | head -1 | cut -d= -f2)
INPUT=$(echo "${LINE}"   | grep -oE 'input=0x[0-9a-fA-F]+'   | head -1 | cut -d= -f2)
SIZE=$(echo "${LINE}"    | grep -oE 'size=0x[0-9a-fA-F]+'    | head -1 | cut -d= -f2)

ok "trigger=${TRIGGER} input=${INPUT} size=${SIZE}"

# ----- 2. Run fwfuzz.py with discovered addresses -------------------------
# fwfuzz.py expects a corpus directory with seed inputs. Seed it with a
# minimal valid syz_edk2 program (header + 1 nop call).
SEED_DIR="${OUTDIR}/seeds"
mkdir -p "${SEED_DIR}"
python3 -c "
import struct, os
# Build a minimal valid program: magic + ncalls(1) + nop record (call=1, size=12, cookie)
buf = struct.pack('<II', 0x53595A45, 1) + struct.pack('<II', 1, 12) + struct.pack('<Q', 0)
open('${SEED_DIR}/seed0', 'wb').write(buf)
print('seed0:', len(buf), 'bytes')
"

# Region: snapshot the entire DRAM range that the firmware uses.
# OVMF DXE drivers live below 0x40000000 in 1 GiB configs.
REGION_LO=0x00000000
REGION_HI=0x40000000

step "starting fwfuzz.py for ${MINUTES} minutes"
# fwfuzz.py uses RELATIVE plugin paths (contrib/plugins/lib*.so), so we
# must chdir into the build directory where those are available.
echo "[wrapper] chdir ${QEMU_BUILD}"
cd "${QEMU_BUILD}" && timeout $((MINUTES * 60)) python3 -u "${QEMU_DIR}/scripts/fwfuzz/fwfuzz.py" \
    --qemu "${QEMU_BIN}" \
    --machine q35,accel=tcg,smm=off \
    --cpu max \
    --memory 1024 \
    --bare \
    --qemu-arg=-nodefaults \
    --qemu-arg=-no-reboot \
    "--qemu-arg=-serial null" \
    "--qemu-arg=-drive if=pflash,format=raw,readonly=on,file=${OVMF_CODE}" \
    "--qemu-arg=-drive if=pflash,format=raw,file=${OUTDIR}/vars.fd" \
    "--qemu-arg=-debugcon file:${OUTDIR}/edk2-debug.log" \
    "--qemu-arg=-global isa-debugcon.iobase=0x402" \
    "--qemu-arg=-object memory-backend-file,id=syzcov,share=on,mem-path=${OUTDIR}/shm,size=256M" \
    "--qemu-arg=-device ivshmem-plain,memdev=syzcov" \
    --trigger "${TRIGGER}" \
    --exit-trigger "${TRIGGER}" \
    --fuzz-addr "${INPUT}" \
    --fuzz-max "$((${SIZE}))" \
    --max-blocks 200000 \
    --region "${REGION_LO}:${REGION_HI}" \
    --corpus "${SEED_DIR}" \
    --output "${OUTDIR}/findings" \
    --max-input-size 4096 \
    --exec-timeout 5 \
    --timeout 180 \
    --callsite-aware \
    2>&1 | tee "${OUTDIR}/fwfuzz.log"

step "campaign complete"
echo "Output: ${OUTDIR}/findings"
ls -la "${OUTDIR}/findings/" 2>/dev/null
