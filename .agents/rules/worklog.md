# Worklog Archiving Rule

This rule ensures that all implementation plans, walkthroughs, and session summaries are preserved directly in `WORKLOG/` in chronological order.

## Guidelines
1. **Target Directory**: `WORKLOG/` in the workspace root.
2. **Chronological Naming Convention**:
   Use ISO timestamp prefix (`YYYY-MM-DD_HH-MM`):
   - Plans: `WORKLOG/YYYY-MM-DD_HH-MM_plan_<topic>.md`
   - Walkthroughs: `WORKLOG/YYYY-MM-DD_HH-MM_walkthrough_<topic>.md`
   - Summaries: `WORKLOG/YYYY-MM-DD_HH-MM_summary_<topic>.md`
3. **Execution**:
   - Write copies whenever an `implementation_plan.md` or `walkthrough.md` is created or updated.
   - Ensure the latest worklog is saved before git commits or closing tasks.
