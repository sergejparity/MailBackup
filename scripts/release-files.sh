#!/usr/bin/env bash
# Release files for a tag (issue #81), used by the `publish` job in
# .github/workflows/build-windows.yml and tested by release-files-test.sh.
#
#   release-files.sh collect <artifact dir> <dist dir> <version>
#       Copies the Windows build's outputs into <dist dir> under fixed names
#       and writes SHA256SUMS there.
#   release-files.sh check <dir>
#       Checks <dir> (a downloaded release) against its SHA256SUMS: every
#       listed file matches, and every file is listed.
#
# Release file names are kept to [A-Za-z0-9._-]: the installers' own names
# contain the product name with a space, which GitHub replaces with a dot on
# upload, so the downloaded names would no longer match SHA256SUMS.
set -euo pipefail

die() {
  echo "release-files: $*" >&2
  exit 1
}

# The single file matching a glob, or an error naming what was looked for.
only_one() {
  local what=$1
  shift
  [ "$#" -eq 1 ] && [ -f "$1" ] || die "expected exactly one $what, found $#: $*"
  printf '%s\n' "$1"
}

# File names from SHA256SUMS, whole (`<64 hex>  <name>`, names may contain
# spaces), one per line.
listed_names() {
  sed -n 's/^[0-9a-f]\{64\} [ *]//p' "$1"
}

collect() {
  local artifact=$1 dist=$2 version=$3
  [[ $version =~ ^[0-9A-Za-z.+-]+$ ]] || die "unexpected version '$version'"
  shopt -s nullglob
  local nsis msi
  nsis=$(only_one "NSIS installer" "$artifact"/bundle/nsis/*.exe)
  msi=$(only_one "MSI installer" "$artifact"/bundle/msi/*.msi)
  shopt -u nullglob

  mkdir -p "$dist"
  cp -- "$artifact/mailbackup.exe" "$dist/mailbackup-cli-windows-x64.exe"
  cp -- "$artifact/mailbackup-server.exe" "$dist/mailbackup-server-windows-x64.exe"
  cp -- "$artifact/mailbackup-gui.exe" "$dist/mailbackup-gui-windows-x64.exe"
  cp -- "$nsis" "$dist/MailBackup-$version-windows-x64-setup.exe"
  cp -- "$msi" "$dist/MailBackup-$version-windows-x64.msi"

  local f
  for f in "$dist"/*; do
    [[ $(basename -- "$f") =~ ^[A-Za-z0-9._-]+$ ]] || die "release file name not allowed: '$(basename -- "$f")'"
  done
  (cd "$dist" && sha256sum -- * > SHA256SUMS)
}

check() {
  local dir=$1
  [ -f "$dir/SHA256SUMS" ] || die "no SHA256SUMS in $dir"
  (cd "$dir" && sha256sum --strict -c SHA256SUMS) || die "checksums don't match"
  local present listed
  present=$(cd "$dir" && find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%f\n' | LC_ALL=C sort)
  listed=$(listed_names "$dir/SHA256SUMS" | LC_ALL=C sort)
  [ -n "$listed" ] || die "SHA256SUMS lists no files"
  if [ "$present" != "$listed" ]; then
    diff <(printf '%s\n' "$present") <(printf '%s\n' "$listed") >&2 || true
    die "the files present and the files listed in SHA256SUMS differ"
  fi
}

case "${1:-}" in
  collect) [ "$#" -eq 4 ] || die "usage: $0 collect <artifact dir> <dist dir> <version>"; collect "$2" "$3" "$4" ;;
  check) [ "$#" -eq 2 ] || die "usage: $0 check <dir>"; check "$2" ;;
  *) die "usage: $0 collect|check ..." ;;
esac
