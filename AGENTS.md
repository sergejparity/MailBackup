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

## Automatic Session Worklog Archiving
All implementation plans, walkthroughs, verification reports, and session summaries must be automatically saved into the `WORKLOG/` directory at the project root in chronological order:

1. **Naming Format**:
   Always use ISO timestamp prefix (`YYYY-MM-DD_HH-MM`) for natural alphanumeric chronological sorting:
   - Implementation plans: `WORKLOG/YYYY-MM-DD_HH-MM_plan_<topic>.md`
   - Walkthroughs / Verification: `WORKLOG/YYYY-MM-DD_HH-MM_walkthrough_<topic>.md`
   - Summaries / Wrap-ups: `WORKLOG/YYYY-MM-DD_HH-MM_summary_<topic>.md`

2. **Trigger Timing**:
   - **On Plan Creation/Approval**: As soon as an implementation plan is approved or finalized, immediately write a copy to `WORKLOG/`.
   - **On Walkthrough / Verification**: As soon as code is tested and verified, write a copy of `walkthrough.md` to `WORKLOG/`.
   - **On Commit / Task Completion**: Before committing code or reporting task completion, ensure the corresponding worklog file exists in `WORKLOG/`.

