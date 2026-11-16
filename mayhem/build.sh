#!/usr/bin/env bash
#
# mayhem/build.sh — builds the AEHD x86 instruction-emulator fuzz target.
#
# AEHD is a Windows kernel driver (MSVC + MASM). Nothing under arch/x86/kvm/ is edited. This script
# compiles upstream's emulate.c on Linux through header shims (mayhem/shim/), translates the MASM
# fastop routines to GAS (mayhem/asm2gas.py), and links them with the harness (mayhem/fuzz_x86_emulate.c).
# The only upstream source change is two MSVC->clang dialect fixes applied to a build-time COPY of
# emulate.c (see "portable copy" below); neither changes behavior.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
B=mayhem/build
rm -rf "$B"
mkdir -p "$B"

# --- portable copy of emulate.c ------------------------------------------------------------------
# 1. emulate.c's X2..X16 repeat-macros are `#define X2(x,...)`; MSVC's preprocessor takes the trailing
#    `...` as an unused parameter, clang's would not expand them the same way. Rewrite the 8 macro
#    definition lines to use __VA_ARGS__ (same expansion, standard C99).
# 2. `insn_fetch(s64, ctxt, (s64)op->val)` takes the address of a cast (an MSVC extension clang rejects);
#    `op->val` is already an s64, so drop the cast (same object, same size).
# `#line` keeps debug info and sanitizer reports pointing at the real upstream file and line numbers.
{
  echo '#line 1 "arch/x86/kvm/emulate.c"'
  sed -E '/^#define X[0-9]+\(x,\.\.\.\)/{s/\(x,\.\.\.\)/(...)/;s/\bx\b/__VA_ARGS__/g};s/insn_fetch\(s64, ctxt, \(s64\)op->val\)/insn_fetch(s64, ctxt, op->val)/' arch/x86/kvm/emulate.c
} > "$B/emulate.c"
n=$(diff <(cat arch/x86/kvm/emulate.c) <(tail -n +2 "$B/emulate.c") | grep -c '^>' || true)
[ "$n" -eq 9 ] || { echo "portable copy of emulate.c changed $n lines, expected exactly 9 (8 X-macros + 1 insn_fetch)" >&2; exit 1; }

# --- MASM -> GAS for the fastop / MMX / SSE helpers (assembly/x64/assembly.asm) -------------------
python3 mayhem/asm2gas.py assembly/x64/assembly.asm "$B/fastop.S"

# AEHD's own types header redefines `volatile`/`false` and expects MSVC; the shims in mayhem/shim/ come first.
INC="-Imayhem/shim -I. -Iinclude -Iarch/x86/include -Iarch/x86/kvm"
DEFS="-D_WIN64 -DCONFIG_X86_64"
MS="-fms-extensions -w -Wno-implicit-int"
# Two UBSan checks are relaxed on emulate.c only (x86 idioms that fire on every input):
#   shift-base : get_canonical() left-shifts a negative value;
#   alignment  : insn_fetch() loads u16/u32/u64 immediates from the unaligned instruction byte buffer.
# Every other ASan/UBSan check stays enabled and halting.
RELAX="-fno-sanitize=shift-base,alignment"
OPT="-O1"

# Instrumented objects (SanCov via fuzzer-no-link, unconditional) for the fuzzer;
# a second set without SanCov for the -standalone reproducer, which has no libFuzzer runtime.
for v in fuzz plain; do
  cov=""; [ "$v" = fuzz ] && cov="-fsanitize=fuzzer-no-link"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $cov $OPT $MS $DEFS $INC $RELAX -c "$B/emulate.c" -o "$B/emulate-$v.o"
  # the fastop helpers are called with a custom register convention and need the red zone off
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $cov $OPT $MS $DEFS $INC -mno-red-zone -c mayhem/fuzz_x86_emulate.c -o "$B/harness-$v.o"
done
$CC $DEBUG_FLAGS -c "$B/fastop.S" -o "$B/fastop.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$B/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"

# --- fuzz target + standalone reproducer ----------------------------------------------------------
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/harness-fuzz.o" "$B/emulate-fuzz.o" "$B/fastop.o" "$B/lsan_off.o" -o /mayhem/fuzz_x86_emulate
$CC $SANITIZER_FLAGS $DEBUG_FLAGS "$B/standalone_main.o" "$B/harness-plain.o" "$B/emulate-plain.o" "$B/fastop.o" "$B/lsan_off.o" -o /mayhem/fuzz_x86_emulate-standalone

# --- known-answer probe for mayhem/test.sh: normal flags, no sanitizers, no SanCov ----------------
$CC -O1 $COVERAGE_FLAGS $MS $DEFS $INC -c "$B/emulate.c" -o "$B/emulate-kat.o" $RELAX
$CC -O1 $COVERAGE_FLAGS $MS $DEFS $INC -mno-red-zone -DKAT_MAIN -c mayhem/fuzz_x86_emulate.c -o "$B/harness-kat.o"
$CC $COVERAGE_FLAGS "$B/harness-kat.o" "$B/emulate-kat.o" "$B/fastop.o" -o /mayhem/aehd_emulate_kat
