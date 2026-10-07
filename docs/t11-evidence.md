# T11 documentation review evidence

Reviewed 2026-10-07 on `feature/T11`, created from updated main
`3a525f049d495646c1adf15c699d755367398230` (T10 PR #62 merge).

## Reconciliation

README preserves the original motivation, objectives, diagrams, team/workflow,
phase plan and full citation list. Each original section is updated in place:
the IPC table describes v1, schema describes canonical tables, alert examples
match actual export fields, and scenario sections show existing validation
commands with evidence limits. Demo/CLI/CI details are integrated into their
sections rather than appended as a duplicate guide. Universal coverage,
prevention and enforced branch protection are not claimed.

Added [architecture](architecture.md), [protocol](protocol.md),
[threat model](threat-model.md), [references](references.md). Updated
[demo guide](collector_demo.md) with observed report shape and summary, and
[issue register](issues.md#current-dispositions-t11) with all I01–I25 dispositions.
Older per-task evidence is historical: its then-pending downstream tasks are
superseded by the current checklist/disposition table.

## Local verification

- `LDWATCH_DEMO_DIR=/tmp/ldwatch-t11-20261007 bash scripts/demo_t10.sh` passed:
  four initial MISSING_BASELINE alerts, zero new clean-run alerts and exactly
  one UNKNOWN_SO deviation. All three deliverables were built by the script.
- `baseline show` displayed approved production v1 with four load entries.
- `diff --source events` identified only the harmless library as UNEXPECTED.
- jq parsed the report as an array and confirmed rule counts 4 + 1.
- `go test ./cmd/ldwatch-cli` passed; no runtime source changed in T11.
- `git diff --check`, `bash -n scripts/demo_t10.sh` and
  `docker compose config --quiet` passed.

## Remote checks, independent of local results

GitHub CLI inspected [main CI run 37483536116](https://github.com/shubh1855/LD-Watch/actions/runs/37483536116).
It completed successfully for the main SHA above. Build-all, artifact check,
race tests, vet, C audit fixtures and artifact upload all succeeded. This is
evidence for merged T10/main, not a claim about a future T11 PR run.

`gh api repos/shubh1855/LD-Watch/branches/main/protection` returned HTTP 404
with “Branch protection has been disabled on this repository.” The README no
longer claims it is enabled. No remote settings were changed.

The initial `gh issue list` check returned `[]`. A subsequent review opened
follow-up issues #64–#68. All five now have merged fixes, including #66 in
PR #73; the #65 scope limitation remains documented.
Deferred feature scope is not implemented by issue closure.

## Synchronization with newer main fixes

Existing PR #63 is retained. The initial sync merged main `df5c531` into
feature/T11, preserving shared branch history. README and demo-guide conflicts
are resolved by retaining both T11 structure/citations and the bounded diagnostic policy.
The provider-set contract update from PR #72 is retained.

That sync included main's fixes for #64/#65/#67/#68. The unrelated T11 report
commit was removed before synchronization; #66 was kept in its separate PR
rather than implemented as part of the documentation work.

Synchronization validation passed: full `go test -race ./...`, C audit suite
18/18, local-link/JSON/fence/conflict-marker checks and whitespace checks.
At that sync, `git diff origin/main -- audit cmd internal scripts tests` was
empty, confirming runtime code matched main. Main's [CI run 37592221940](https://github.com/shubh1855/LD-Watch/actions/runs/37592221940)
also passed for `df5c531f629811fe86ca0c08d37a3910a0e9dfa2`; the updated T11 PR
must run its own checks after pushing.

### Report-fix synchronization (2026-10-07)

Main `4ba6ed0` (PR #73) is merged into the existing T11 branch without rewriting
shared history. Report documentation now describes SQL-filtered, unbounded
single-snapshot exports and the remaining memory-buffering limitation. Issue
#66 is recorded as fixed. The current persistence guide lists migration 005
and schema version 5, including preservation of existing canonical alerts.

The manual setup script's printed query now selects canonical `loader_events`,
not archival `so_events`; its setup/reset behavior is unchanged. Socket guidance
continues to require 0660 access. Existing README sections and citations remain
intact. Audit, collector, CLI, store and test sources match main; the only script
change is that printed query.

Synchronization verification passed:

- `GOCACHE=/tmp/ldwatch-issue64-cache go test -race ./...` and `go vet ./...`.
- `bash scripts/test_audit.sh`: 18 passed, 0 failed.
- `LDWATCH_DEMO_DIR=/tmp/ldwatch-t11-docsync.UVvbPn bash scripts/demo_t10.sh`:
  all deliverables built, four initial coverage alerts, no additional clean-run
  alerts and one deviation; jq confirmed the five-entry report and rule counts.
- The setup script's exact printed query returned canonical telemetry from
  that demo database; setup/reset itself was not executed against system data.
- `bash -n scripts/demo_collector_setup.sh scripts/demo_t10.sh`,
  `docker compose config --quiet` and `git diff --check`.
- Markdown checks passed for 14 files, 88 local links and two JSON examples;
  README headings and its full References section are unchanged from the
  pre-sync T11 commit `29ee0da`.
- `git diff origin/main -- audit cmd internal tests` was empty. GitHub's open
  issue list returned `[]`; no issues or repository settings were modified.

These are local checks of the updated branch, not a claim about its next CI run.

## Explicit follow-ups and accepted limits

- Repository owner may enable main branch protection and required review/CI.
- IEEE identifiers 10753555 and 10538975 require manual bibliography checking:
  publisher pages returned verification screens. They are excluded from
  verified citations; [references](references.md) preserves the original claims.
- Four other academic references were checked against primary pages/PDF and
  two titles corrected. They supply context, not LD-Watch implementation proof.
- Compose configuration is checked; a fresh full container build/run was not
  performed for T11. Host Linux demo and remote Ubuntu CI have separate evidence.
- PRELOAD_PRIVILEGED, static/system-wide observation, content integrity and
  durable loss recovery remain future work with [threat-model](threat-model.md)
  limits. No universal prevention, tamper-proof or no-loss guarantee is made.

## Gate

Passed documentation reconciliation locally 2026-10-07: advertised capabilities
are tied to implementation/evidence; unresolved scope and external checks have
explicit dispositions. Teammate review and T11 PR CI remain normal merge gates.
