#!/usr/bin/env bash
#
# mayhem/build.sh — build the alerts.log parser fuzz harness (GetAlertData) and OSSEC's libcheck unit tests.
# Runs inside the commit image as `mayhem` in /mayhem. Re-runnable and offline: every dependency
# (check, subunit, pcre2, zlib) is an apt package installed by mayhem/Dockerfile.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC/src"

# Plain Linux build without the optional systemd/libmagic/hardening link deps.
MK=(USE_HARDENING=no USE_SYSTEMD=no USE_MAGIC=no)
TESTS=(test_os_zlib test_os_xml test_os_regex test_os_crypto test_shared)

# 1) Unit tests first, with the project's NORMAL flags (no sanitizers, no coverage unless asked).
make -s clean-internals clean-test >/dev/null 2>&1 || true
rm -f external/cJSON/cJSON.o libcJSON.a
# CFLAGS/LDFLAGS go through the environment: a command-line CFLAGS= would override the Makefile's own
# `CFLAGS+=` additions (include paths for the bundled compat headers).
CFLAGS="$COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS" \
    make -j"$MAYHEM_JOBS" "${MK[@]}" TEST=1 DEBUG=1 CFLAGS_TEST="-g -O0" "${TESTS[@]}"

# 2) Sanitized project libraries, then wipe the test objects they share a tree with.
rm -f tests/*.o
make -s clean-internals >/dev/null 2>&1 || true
rm -f external/cJSON/cJSON.o libcJSON.a
# -fsanitize=fuzzer-no-link adds libFuzzer's coverage instrumentation to the project code itself
# (otherwise only the harness is instrumented and the fuzzer sees no feedback from shared/read-alert.c).
COV_FLAGS="-fsanitize=fuzzer-no-link"
CFLAGS="-O1 -fPIC $SANITIZER_FLAGS $COV_FLAGS $DEBUG_FLAGS" LDFLAGS= \
    make -j"$MAYHEM_JOBS" "${MK[@]}" shared.a os_xml.a os_net.a os_regex.a libcJSON.a

# 3) Harnesses: libFuzzer binary + standalone reproducer, both with leak detection switched off.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o /tmp/lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main.o

build_harness() {
    local name="$1" src="$2"; shift 2
    $CC $SANITIZER_FLAGS $COV_FLAGS $DEBUG_FLAGS -DOSSECHIDS -DLinux -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE -DDEFAULTDIR=\"/var/ossec\" -DARGV0=\"fuzz_read_alert\" -I./ -I./headers/ -I./os_xml -I./os_regex -I./external/compat -c "$src" -o "/tmp/$name.o"
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS "/tmp/$name.o" /tmp/lsan_off.o "$@" $LIB_FUZZING_ENGINE -o "/mayhem/$name"
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS "/tmp/$name.o" /tmp/lsan_off.o /tmp/standalone_main.o "$@" $COV_FLAGS -o "/mayhem/$name-standalone"
}

build_harness fuzz_read_alert "$SRC/mayhem/harnesses/fuzz_read_alert.c" \
    -Wl,--start-group shared.a os_xml.a os_net.a os_regex.a libcJSON.a -Wl,--end-group -lpcre2-8 -lm -lpthread
