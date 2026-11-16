#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Known-answer test of the AEHD x86 instruction emulator. /mayhem/aehd_emulate_kat (built by build.sh with
# normal flags, no sanitizers) decodes and emulates fixed instruction bytes from a fixed register file and
# flat segments, then prints the resulting GPRs, EFLAGS, EIP delta, exception vector and operand size.
# Each line below is the architecturally correct result (e.g. 0x11111111+0x22222222=0x33333333 with PF set;
# 100/7 = 14 rem 2; DIV by zero raises #DE (vector 0); LOCK MOV raises #UD (vector 6)).
KAT="$SRC/aehd_emulate_kat"
if [ ! -x "$KAT" ]; then
  echo "missing $KAT: mayhem/build.sh did not build it" >&2
  emit_ctrf "aehd-emulate-kat" 0 1 0
  exit 1
fi

EXPECTED='add rc=0 eax=33333333 ecx=0 edx=0 ebx=22222222 eflags=4 eip=2 len=2 vec=-1 opb=4
sub rc=0 eax=fffffffe ecx=0 edx=0 ebx=7 eflags=91 eip=2 len=2 vec=-1 opb=4
div rc=0 eax=e ecx=7 edx=2 ebx=0 eflags=0 eip=2 len=2 vec=-1 opb=4
div0 rc=0 eax=64 ecx=0 edx=0 ebx=0 eflags=0 eip=0 len=2 vec=0 opb=4
shl rc=0 eax=f0 ecx=0 edx=0 ebx=0 eflags=4 eip=3 len=3 vec=-1 opb=4
movimm rc=0 eax=12345678 ecx=0 edx=0 ebx=0 eflags=0 eip=5 len=5 vec=-1 opb=4
lea rc=0 eax=1020 ecx=20 edx=0 ebx=1000 eflags=0 eip=3 len=3 vec=-1 opb=4
opsize16 rc=0 eax=11113333 ecx=0 edx=0 ebx=22222222 eflags=4 eip=3 len=3 vec=-1 opb=2
rexw_add rc=0 eax=33333333 ecx=0 edx=0 ebx=22222222 eflags=4 eip=3 len=3 vec=-1 opb=8
jz_taken rc=0 eax=0 ecx=0 edx=0 ebx=0 eflags=40 eip=7 len=2 vec=-1 opb=4
jz_not_taken rc=0 eax=0 ecx=0 edx=0 ebx=0 eflags=0 eip=2 len=2 vec=-1 opb=4
bswap rc=0 eax=80 ecx=0 edx=0 ebx=0 eflags=0 eip=2 len=2 vec=-1 opb=4
xor rc=0 eax=ff ecx=0 edx=0 ebx=f eflags=4 eip=2 len=2 vec=-1 opb=4
lock_mov rc=0 eax=11111111 ecx=0 edx=0 ebx=22222222 eflags=0 eip=0 len=3 vec=6 opb=4
undef rc=0 eax=0 ecx=0 edx=0 ebx=0 eflags=0 eip=0 len=1 vec=6 opb=8'

ACTUAL="$("$KAT" 2>&1 || true)"
passed=0; failed=0
while IFS= read -r want; do
  name="${want%% *}"
  if printf '%s\n' "$ACTUAL" | grep -Fxq -- "$want"; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL $name"
    echo "  want: $want"
    echo "  got:  $(printf '%s\n' "$ACTUAL" | grep -F -- "$name " || echo '<no output>')"
  fi
done <<< "$EXPECTED"

emit_ctrf "aehd-emulate-kat" "$passed" "$failed" 0
