#!/usr/bin/env bash
#
# mayhem/test.sh — RUN OSSEC's own libcheck unit tests (os_zlib, os_xml, os_regex, os_crypto, shared),
# which mayhem/build.sh already built in src/. Each binary prints "NN%: Checks: C, Failures: F, Errors: E";
# a binary that prints no such line (crashed, or neutered into a no-op) counts as a failure.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC/src"

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

passed=0 ; failed=0
for t in test_os_zlib test_os_xml test_os_regex test_os_crypto test_shared; do
  if [ ! -x "./$t" ]; then
    echo "missing test runner ./$t (mayhem/build.sh should have built it)" >&2
    failed=$((failed + 1)) ; continue
  fi
  out=$("./$t" 2>&1) ; rc=$?
  echo "$out"
  line=$(printf '%s\n' "$out" | grep -E '^[0-9]+%: Checks: [0-9]+, Failures: [0-9]+, Errors: [0-9]+' | tail -1)
  if [ -z "$line" ]; then
    echo "$t produced no libcheck summary (rc=$rc)" >&2
    failed=$((failed + 1)) ; continue
  fi
  c=$(sed -E 's/.*Checks: ([0-9]+),.*/\1/' <<<"$line")
  f=$(sed -E 's/.*Failures: ([0-9]+),.*/\1/' <<<"$line")
  e=$(sed -E 's/.*Errors: ([0-9]+).*/\1/' <<<"$line")
  bad=$((f + e))
  [ "$rc" -eq 0 ] || [ "$bad" -gt 0 ] || bad=1
  [ "$c" -gt 0 ] || bad=1
  passed=$((passed + c - (bad > c ? c : bad)))
  failed=$((failed + bad))
done
emit_ctrf "libcheck" "$passed" "$failed" 0
