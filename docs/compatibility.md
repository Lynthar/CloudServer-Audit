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
| `audit` | 0 | complete scan — every selected module finished |
| `audit` | 3 | one or more modules did not finish: one failed to load or crashed, a check could not be recorded, a filesystem walk hit `VPSSEC_FS_TIMEOUT`, or the configuration every check of a module judges could not be read (`sshd -T`, `nginx -T`); the names are in `meta.modules_failed` |
| `guide` | 0 | no fix in the executed plan failed, and its last audit finished with every module loaded — a fix the operator answered "no" to at its confirmation is skipped, not failed, and the summary names it |
| `guide` | 3 | no fix failed (or none was available), but its last audit did not finish, for the reasons `audit` exits 3 (a module that failed to load counts against every audit of the run); the names are in `meta.modules_failed` |
| `guide` | 4 | unsupported distro (not Debian/Ubuntu) — nothing was changed |
| `rollback` | 0 | the requested restore completed (also: cancelled at the prompt) |
| `rollback` | 2 | the restore ran but skipped some entries (a missing list of the files the plan created counts as one), or restored a file whose original mode was not on record (counted in the output, named in `logs/vpssec.log`); services were still reloaded |
| any | 1 | error — not root, bad arguments (including `VPSSEC_FS_TIMEOUT` and an unknown `--include` module), a failed fix, nothing restored, a report file that could not be written, … |
| `run.sh` | 2 | `guide`/`rollback` refused under the run-once entry point, whether named on its command line, picked in the mode menu, or set through `VPSSEC_MODE` |

Never "fix" a red CI by mapping 3 or 4 back to 0: they exist so that an
incomplete scan or an unsupported capability cannot read as success.

**Deprecated, changes in the next MAJOR release:** a `rollback` declined at its
confirmation prompt, or unable to read one because there is no terminal, exits 0
today; it will exit 1, the same code as "nothing restored", so automation can
tell a restore from no restore. `guide` cancelled at its fix selection for the
same reasons will likewise exit 1 instead of 0.

## Reports

- **When reports are written:** always with `--json-only` or `--yes`; otherwise
  only if the operator answers yes at the end of the audit. Files already in
  `reports/` are never deleted, so check `meta.timestamp` before trusting one.
- **`reports/summary.json`** is the machine interface. The top-level shape —
  `meta`, `stats`, `checks[]` — and existing field names are removed or
  renamed only in a MAJOR release; new fields may appear in any MINOR, so
  consumers must ignore unknown fields. With `--json-only`, stdout is
  exactly this JSON document; everything else goes to stderr. Each entry in
  `checks[]` carries `scored`: whether it counts toward this run's score
  (it can depend on `--strict` and on what is installed).
- **`reports/summary.sarif`** is SARIF 2.1.0, kept valid against the
  official schema.
- **`reports/summary.md`** is for humans and is NOT a stable interface.

## Score

The formula (user guide, Appendix B) changes only in a MAJOR release.
Adding checks in a MINOR release can still move absolute scores — compare
scores only between runs of the same version and module set, and read
`meta.partial_scope` / `stats.scored_total` before comparing anything.
