# Developer & Agent Guidelines

## Workspace Versioning
This repository follows Semantic Versioning (`MAJOR.MINOR.PATCH`).
Workspace versions are defined centrally in `Cargo.toml` under `[workspace.package]`.
The desktop GUI version is tracked in `crates/mailbackup-gui/tauri.conf.json`.

Whenever implementing features or bug fixes:
1. Always bump the patch version (or minor version for major functional additions) before committing.
2. Use the provided script:
   ```bash
   ./scripts/bump.sh patch
   ```
   or
   ```bash
   ./scripts/bump.sh minor
   ```
3. This script ensures `Cargo.toml`, `Cargo.lock`, and `tauri.conf.json` stay synchronized.
