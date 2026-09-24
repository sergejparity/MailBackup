# Version Management Rules

This repository follows Semantic Versioning (`MAJOR.MINOR.PATCH`).
All packages in the workspace inherit their version from `[workspace.package]` in the root `Cargo.toml`.
The desktop GUI (`crates/mailbackup-gui/tauri.conf.json`) must always match this version.

## Bumping Guidelines
1. **Patch version bump (`0.1.x` -> `0.1.x+1`)**:
   - For bug fixes, UI improvements, error handling, refactors, and minor feature extensions.
2. **Minor version bump (`0.1.x` -> `0.2.0`)**:
   - For major features (e.g., adding whole new subsystem, new backup engines, authentication overhauls).
3. **Major version bump (`0.x.y` -> `1.0.0`)**:
   - For public API stability / 1.0 production release.

## Execution Procedure
Before committing completed work:
- Run `./scripts/bump.sh patch` (or `minor`).
- Alternatively, ensure both `Cargo.toml` and `crates/mailbackup-gui/tauri.conf.json` are updated to the same version, and run `cargo check --workspace` to update `Cargo.lock`.
- Stage `Cargo.toml`, `Cargo.lock`, and `tauri.conf.json` alongside the feature/bugfix files.
