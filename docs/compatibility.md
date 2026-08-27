# Compatibility contract

What an integration may depend on, and which version bump is allowed to
change it. Versions are semver (`MAJOR.MINOR.PATCH`); this contract applies
from v1.3.0. Anything not listed here — internal file layouts, `state/`,
log formats, i18n keys, function names — is not an interface and may change
in any release.

## Stable identifiers

- **`check_id` and `fix_id` are stable names.** They are renamed or removed
  only in a MAJOR release; new ones may appear in any MINOR. Pin dashboards,
  suppressions and tooling to these, never to display text — titles and
  descriptions are localized and rewritten freely.
- **CLI flags** documented in the README are removed or repurposed only in a
  MAJOR release.

## Exit codes

Codes listed here change meaning only in a MAJOR release; codes not listed
are not part of the contract.

| Command | Code | Meaning |
|---|---|---|
| `audit` | 0 | complete scan — every selected module finished; reports written |
| `audit` | 3 | one or more modules did not finish; reports are still written, the names are in `meta.modules_failed` |
| `guide` | 0 | every fix in the executed plan succeeded |
| `guide` | 4 | unsupported distro (not Debian/Ubuntu) — nothing was changed |
| `rollback` | 0 | the requested restore completed (also: cancelled at the prompt) |
| any | 1 | error — not root, bad arguments, a failed fix, nothing restored, … |
| `run.sh <cmd>` | 2 | `guide`/`rollback` refused under the run-once entry point |

Never "fix" a red CI by mapping 3 or 4 back to 0: they exist so that an
incomplete scan or an unsupported capability cannot read as success.

## Reports

- **`reports/summary.json`** is the machine interface. The top-level shape —
  `meta`, `stats`, `checks[]` — and existing field names are removed or
  renamed only in a MAJOR release; new fields may appear in any MINOR, so
  consumers must ignore unknown fields. With `--json-only`, stdout is
  exactly this JSON document; everything else goes to stderr.
- **`reports/summary.sarif`** is SARIF 2.1.0, kept valid against the
  official schema.
- **`reports/summary.md`** is for humans and is NOT a stable interface.

## Score

The formula (README → Security score) changes only in a MAJOR release.
Adding checks in a MINOR release can still move absolute scores — compare
scores only between runs of the same version and module set, and read
`meta.partial_scope` / `stats.scored_total` before comparing anything.
