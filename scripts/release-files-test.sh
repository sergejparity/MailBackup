#!/usr/bin/env bash
# Tests for release-files.sh, with the installer names the Windows build
# really produces (the product name contains a space). Run by CI (Linux).
set -euo pipefail

script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/release-files.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failures=0

pass() { echo "ok   - $1"; }
fail() { echo "FAIL - $1"; failures=$((failures + 1)); }
expect_ok() { local name=$1; shift; if "$@" >/dev/null 2>&1; then pass "$name"; else fail "$name"; fi; }
expect_fail() { local name=$1; shift; if "$@" >/dev/null 2>&1; then fail "$name"; else pass "$name"; fi; }

# A build artifact as upload-artifact lays it out
artifact() {
  local dir=$1
  mkdir -p "$dir/bundle/nsis" "$dir/bundle/msi"
  for f in mailbackup.exe mailbackup-server.exe mailbackup-gui.exe; do echo "$f" > "$dir/$f"; done
  echo nsis > "$dir/bundle/nsis/MailBackup Studio_0.9.0_x64-setup.exe"
  echo msi > "$dir/bundle/msi/MailBackup Studio_0.9.0_x64_en-US.msi"
}

artifact "$work/a"
expect_ok "collect with installer names containing spaces" "$script" collect "$work/a" "$work/dist" 0.9.0
expected="MailBackup-0.9.0-windows-x64-setup.exe
MailBackup-0.9.0-windows-x64.msi
SHA256SUMS
mailbackup-cli-windows-x64.exe
mailbackup-gui-windows-x64.exe
mailbackup-server-windows-x64.exe"
actual=$(cd "$work/dist" && ls -1 | LC_ALL=C sort)
if [ "$actual" = "$expected" ]; then pass "release files have fixed, space-free names"; else fail "release files: $actual"; fi
if [ "$(grep -c . "$work/dist/SHA256SUMS")" = 5 ]; then pass "SHA256SUMS lists five files"; else fail "SHA256SUMS line count"; fi
expect_ok "check passes on the collected files" "$script" check "$work/dist"

# A downloaded release that differs from its SHA256SUMS
cp -r "$work/dist" "$work/extra" && echo x > "$work/extra/unlisted.exe"
expect_fail "check fails on an unlisted file" "$script" check "$work/extra"
cp -r "$work/dist" "$work/missing" && rm "$work/missing/mailbackup-cli-windows-x64.exe"
expect_fail "check fails on a missing file" "$script" check "$work/missing"
cp -r "$work/dist" "$work/changed" && echo tampered >> "$work/changed/MailBackup-0.9.0-windows-x64.msi"
expect_fail "check fails on a changed file" "$script" check "$work/changed"
# As if GitHub had renamed an asset on upload ("a b" -> "a.b")
mkdir "$work/renamed" && echo same > "$work/renamed/a.b.exe"
(cd "$work/renamed" && echo "$(sha256sum < a.b.exe | cut -d' ' -f1)  a b.exe" > SHA256SUMS)
expect_fail "check fails when a listed name with a space was renamed" "$script" check "$work/renamed"
# Names with spaces are compared whole, not cut at the space
mkdir "$work/spaced" && echo one > "$work/spaced/My App.exe" && echo two > "$work/spaced/My Other.exe"
(cd "$work/spaced" && sha256sum -- * > SHA256SUMS)
expect_ok "check compares whole names that contain spaces" "$script" check "$work/spaced"

# Collect refuses what it can't name
artifact "$work/two" && echo nsis2 > "$work/two/bundle/nsis/Other_x64-setup.exe"
expect_fail "collect fails on two NSIS installers" "$script" collect "$work/two" "$work/dist2" 0.9.0
artifact "$work/none" && rm "$work/none/bundle/msi/"*.msi
expect_fail "collect fails without an MSI" "$script" collect "$work/none" "$work/dist3" 0.9.0
artifact "$work/nocli" && rm "$work/nocli/mailbackup.exe"
expect_fail "collect fails without the CLI" "$script" collect "$work/nocli" "$work/dist4" 0.9.0
artifact "$work/badver"
expect_fail "collect refuses a version with a space" "$script" collect "$work/badver" "$work/dist5" "0.9 .0"

[ "$failures" -eq 0 ] || { echo "$failures failed"; exit 1; }
echo "all passed"
