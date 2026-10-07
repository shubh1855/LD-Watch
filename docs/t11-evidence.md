# T11 documentation review evidence

Reviewed 2026-10-07 on `feature/T11`, created from updated main
`3a525f049d495646c1adf15c699d755367398230` (T10 PR #62 merge).

## Reconciliation

README now describes actual component paths, standard Go flag CLI, v1 framing,
canonical tables, approved profiles and existing tests/commands. Removed claims
for nonexistent shell tests/attack directories, native-layout wire structs,
universal program coverage, prevention and completed remote protection.

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

`gh issue list --state open --limit 50 --json number,title,url` returned `[]`.
Implementation dispositions are retained locally even though GitHub currently
has no open issues. Deferred feature scope is not implemented by issue closure.

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
