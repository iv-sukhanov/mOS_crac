#!/bin/bash
# Run pac_probe (NOTES.md 2026-09-10) inside a macOS VM to check whether
# ad-hoc arm64e binaries get a shared (per-boot) or per-process A key on
# this OS version.
#
# Host side:
#   clang -g -O0 -arch arm64e -mmacosx-version-min=26.0 -o /tmp/pac_probe_e tests/pac_probe.c
#   clang -g -O0 -arch arm64  -mmacosx-version-min=26.0 -o /tmp/pac_probe_a tests/pac_probe.c
#   clang -g -O0 -o /tmp/spawn_noaslr tests/spawn_noaslr.c
#   scp /tmp/pac_probe_e /tmp/pac_probe_a /tmp/spawn_noaslr tests/run_probe.sh admin@$VMIP:~/probe/
#   ssh admin@$VMIP 'chmod +x ~/probe/* && ~/probe/run_probe.sh'
#
# Reading: PACIZA(printf) identical across the 3 runs -> shared A key;
#          differs every run -> per-process A key. cache_base / &stackvar
#          identical across runs confirms ASLR is pinned (control).

set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
RUNS="${1:-3}"

echo "=== $(sw_vers -productVersion) ($(sw_vers -buildVersion)) $(uname -m) ==="
echo "SIP: $(csrutil status 2>/dev/null || echo '?')"
sysctl hw.optional.arm.FEAT_FPAC hw.optional.arm.FEAT_FPACCOMBINE machdep.ptrauth_enabled 2>/dev/null
echo

echo "########## arm64e ##########"
for i in $(seq 1 "$RUNS"); do
    echo "----- run $i -----"
    "$DIR/spawn_noaslr" "$DIR/pac_probe_e"
done

if [ -x "$DIR/pac_probe_a" ]; then
    echo
    echo "########## plain arm64 (control: PAC should be a no-op) ##########"
    for i in $(seq 1 "$RUNS"); do
        echo "----- run $i -----"
        "$DIR/spawn_noaslr" "$DIR/pac_probe_a" | grep -E 'PACIZA|PACDZA|cache_base'
    done
fi
