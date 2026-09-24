#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# MailBackup Workspace Version Bumping Script
#
# Usage:
#   ./scripts/bump.sh [patch|minor|major|<specific-version>] [--commit] [--tag] [--push]
#
# Examples:
#   ./scripts/bump.sh patch
#   ./scripts/bump.sh minor --commit
#   ./scripts/bump.sh 0.2.0 --commit --tag --push
# ---------------------------------------------------------------------------

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO_TOML="$ROOT_DIR/Cargo.toml"
TAURI_CONF="$ROOT_DIR/crates/mailbackup-gui/tauri.conf.json"

MODE="patch"
DO_COMMIT=false
DO_TAG=false
DO_PUSH=false

for arg in "$@"; do
  case "$arg" in
    patch|minor|major)
      MODE="$arg"
      ;;
    -c|--commit)
      DO_COMMIT=true
      ;;
    -t|--tag)
      DO_TAG=true
      ;;
    -p|--push)
      DO_PUSH=true
      ;;
    -h|--help)
      echo "Usage: $0 [patch|minor|major|<version>] [--commit|-c] [--tag|-t] [--push|-p]"
      exit 0
      ;;
    [0-9]*.[0-9]*.[0-9]*)
      MODE="$arg"
      ;;
    *)
      echo "Error: Unknown argument '$arg'" >&2
      echo "Usage: $0 [patch|minor|major|<version>] [--commit|-c] [--tag|-t] [--push|-p]" >&2
      exit 1
      ;;
  esac
done

if [[ ! -f "$CARGO_TOML" ]]; then
  echo "Error: Cannot find root Cargo.toml at $CARGO_TOML" >&2
  exit 1
fi

python3 - <<EOF
import re
import sys
import subprocess

cargo_toml_path = "$CARGO_TOML"
tauri_conf_path = "$TAURI_CONF"
mode = "$MODE"

with open(cargo_toml_path, "r", encoding="utf-8") as f:
    cargo_content = f.read()

# Extract current version from [workspace.package]
match = re.search(r'\[workspace\.package\][\s\S]*?version\s*=\s*"([^"]+)"', cargo_content)
if not match:
    print("Error: Could not find version in [workspace.package] in Cargo.toml", file=sys.stderr)
    sys.exit(1)

old_version = match.group(1)
parts = old_version.split(".")
if len(parts) != 3 or not all(p.isdigit() for p in parts):
    print(f"Error: Current version '{old_version}' is not valid SemVer (X.Y.Z)", file=sys.stderr)
    sys.exit(1)

major, minor, patch = map(int, parts)

if mode == "patch":
    patch += 1
    new_version = f"{major}.{minor}.{patch}"
elif mode == "minor":
    minor += 1
    patch = 0
    new_version = f"{major}.{minor}.{patch}"
elif mode == "major":
    major += 1
    minor = 0
    patch = 0
    new_version = f"{major}.{minor}.{patch}"
else:
    new_version = mode

print(f"Bumping version: {old_version} -> {new_version}")

# 1. Update Cargo.toml
def replace_cargo_version(m):
    block = m.group(0)
    return re.sub(r'version\s*=\s*"[^"]+"', f'version = "{new_version}"', block, count=1)

new_cargo_content = re.sub(
    r'\[workspace\.package\][\s\S]*?version\s*=\s*"[^"]+"',
    replace_cargo_version,
    cargo_content,
    count=1
)
with open(cargo_toml_path, "w", encoding="utf-8") as f:
    f.write(new_cargo_content)

# 2. Update tauri.conf.json if exists
import os
if os.path.exists(tauri_conf_path):
    with open(tauri_conf_path, "r", encoding="utf-8") as f:
        tauri_content = f.read()
    new_tauri = re.sub(
        r'("package"\s*:\s*\{[\s\S]*?"version"\s*:\s*)"[^"]+"',
        r'\g<1>"' + new_version + '"',
        tauri_content,
        count=1
    )
    with open(tauri_conf_path, "w", encoding="utf-8") as f:
        f.write(new_tauri)

print("Updated Cargo.toml and tauri.conf.json")
EOF

echo "Synchronizing Cargo.lock via 'cargo check --workspace'..."
(cd "$ROOT_DIR" && cargo check --workspace --quiet)

NEW_VERSION=$(grep -m1 '^version' "$CARGO_TOML" | head -n1 | cut -d '"' -f2)
echo "✅ Successfully bumped version to v$NEW_VERSION"

if [ "$DO_COMMIT" = true ]; then
  echo "Committing version bump..."
  git -C "$ROOT_DIR" add Cargo.toml Cargo.lock crates/mailbackup-gui/tauri.conf.json
  git -C "$ROOT_DIR" commit -m "chore: bump version to v$NEW_VERSION"
  echo "✅ Committed: chore: bump version to v$NEW_VERSION"
fi

if [ "$DO_TAG" = true ]; then
  echo "Creating tag v$NEW_VERSION..."
  git -C "$ROOT_DIR" tag -a "v$NEW_VERSION" -m "Release v$NEW_VERSION"
  echo "✅ Tagged: v$NEW_VERSION"
fi

if [ "$DO_PUSH" = true ]; then
  echo "Pushing changes and tags to origin..."
  git -C "$ROOT_DIR" push origin HEAD
  if [ "$DO_TAG" = true ]; then
    git -C "$ROOT_DIR" push origin "v$NEW_VERSION"
  fi
  echo "✅ Pushed to origin"
fi
