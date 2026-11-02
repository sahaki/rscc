# RSCC PHP Source Review

**RSCC** stands for **Review Source Code for Cybersecurity** (the connecting word "for" is omitted from the initialism). It describes reviewing source code for security issues.

Review PHP applications, modules, extensions, plugins, or explicitly selected source files against current international security references. The skill reads source, records evidence and verification gaps, and saves English Markdown reports under the project root's `rscc/` folder. It does not modify application code or create external tasks.

## Three ways to invoke the skill

These are AI request examples using slash notation. The skill can also be named as `$rscc-php-source-review` with the same paths. Quote paths containing spaces. Always identify the source scope explicitly; if the project root is not clear from the workspace, include it in your request.

### 1. Review a folder

```text
/rscc-php-source-review /wp/wp-content/plugins/reepay-checkout-gateway/
```

The skill reads this folder's `.gitignore` afresh on every run, then inventories only this folder, applies fixed and local ignore exclusions, and sorts the remaining files into inspection tiers ([triage policy](references/triage-policy.md)): PHP, JS/TS, executable configuration and unknown files are read in full (T3); passive binaries (T1) and text assets such as CSS, translations, docs and lockfiles (T2) are covered by an automated scan unless a guard promotes them to T3. Use `--no-triage` on `inventory` for an exhaustive full read. It creates or refreshes:

```text
/wp/rscc/reepay-checkout-gateway/structure_file.md
```

The map explains each file's purpose, important functions/hooks, behavior, dependencies, and security boundaries. It must be refreshed on every folder review before the security review starts. The map is then the checklist: every inventoried file receives a review outcome or an explicit limitation. No sampling or silent omissions are allowed.

Reports are saved in:

```text
/wp/rscc/reepay-checkout-gateway/yyyymmdd_hhmm/
```

### 2. Review one file

```text
/rscc-php-source-review /wp/wp-content/plugins/reepay-checkout-gateway/aaa.php
```

The skill reads and reviews only `aaa.php`. It skips directory scanning and does not create, update, or require `structure_file.md`. Existing folder maps are preserved. Imported/included files are not opened automatically.

### 3. Review a list of files

```text
/rscc-php-source-review
/wp/wp-content/plugins/reepay-checkout-gateway/aaa.php
/wp/wp-content/plugins/reepay-checkout-gateway/bbb.php
/wp/wp-content/plugins/reepay-checkout-gateway/ccc.php
```

The explicit list is the review checklist. Every selected file is read in full and reviewed; relationships are traced only among those files. No sibling, parent, or root-wide source scan is performed. Repeated paths are reviewed once. Files can come from different folders within one project. Different projects or an ambiguous mix of folders and files require clarification.

Both file forms save their results together in a new run:

```text
/wp/rscc/file-reviews/yyyymmdd_hhmm/
```

File-mode report paths are relative to the project root, so identical filenames in different folders remain distinguishable. Folder-mode report paths are relative to the selected folder.

## What each run produces

| File | Purpose |
| --- | --- |
| `inventory.json` | Exact selected scope, file hashes, exclusions, and scan/run metadata. In file mode this contains only the explicit file list. |
| `triage.json` | Folder mode only: inspection tier (T1/T2/T3), mode, reason, and scan facts per file. |
| `review.json` | Per-file reading state, checks, statuses, and finding associations. |
| `standards.md` | Official standards sources, versions, access dates, applicability, and verification limitations. |
| `review-summary.md` | Scope, control assessment, important flows, finding summary, and unresolved evidence. |
| `file-review.md` | One result row for every in-scope file, plus detailed checks and evidence. |
| `findings.md` | Issues with type, severity, affected files/lines, evidence, impact, remediation, and acceptance criteria suitable for later tasks. |
| `coverage.md` | Reading coverage, blocked/unreviewed files, scope boundary, and source-change detection. |

Folder mode also maintains the shared `structure_file.md` and `file_notes.json` and copies them into each run. File mode creates neither artifact. All reports are English. A new real `yyyymmdd_hhmm` directory is used per run; if the minute already has a run, the skill waits for the next minute instead of overwriting it.

## Scope and exclusions

The project root determines where reports are saved; it is not an implicit source target. The first scan already uses the selected folder or file list. Missing paths stop the request without falling back to a broader scan. Whole-project scanning requires an explicit whole-root request.

Directories named exactly `vendor`, `node_modules`, `build`, `.git`, `.github`, `.gitlab`, and `.gitea` are excluded at every depth, together with the project's actual `rscc` output tree. Their contents are not read or counted as PASS. An explicitly listed file inside an excluded directory is rejected rather than silently included or dropped. Ordinary `.gitignore`, `.gitattributes`, `.gitmodules`, manifests, and lockfiles outside those directories remain eligible for review.

In **folder mode**, `.gitignore` files in the selected folder and visited non-excluded subfolders add file/folder exclusions. They are read again even if an older structure map exists. Patterns follow [Git's documented rules](https://git-scm.com/docs/gitignore), including wildcards, anchored paths, nested precedence, and `!` reinclusion. Ignored directories are pruned before their contents are read; `!` cannot reopen an ignored parent or override the fixed exclusions. The structure map and coverage report list ignore-rule sources/line numbers, active patterns, and encountered excluded paths. Rule metadata is tracked even if the ignore file excludes itself. Rules above the selected target, global ignores, and source repository Git metadata are not consulted.

Git CLI is required when local `.gitignore` files exist. The helper uses an isolated temporary Git matcher with copies of those ignore files only; it neither scans nor changes the actual repository. Missing Git or unreadable ignore metadata stops the scan rather than broadening it. Changes to ignore metadata invalidate the snapshot. **Single-file/list mode does not read `.gitignore`**: explicitly selected files can be reviewed even if a folder-mode pattern would ignore them, while fixed directory/output exclusions still apply.

## Standards and interpretation

The skill checks current official releases on every run. References include OWASP ASVS, OWASP Top 10, OWASP Cheat Sheets, CWE, CVE/CVSS, OWASP WSTG, CIS Benchmarks, NIST SSDF, and PCI DSS, with applicability and limitations recorded.

| Status | Meaning |
| --- | --- |
| PASS | The assessed applicable controls have supporting source evidence. |
| FAIL | A supported issue violates an assessed control. |
| NEEDS VERIFICATION | Missing selected-source, host, configuration, or runtime evidence prevents a conclusion. |
| NOT APPLICABLE | A control or passive folder-inventory file is outside the demonstrated applicability, with a reason. |
| UNREVIEWED | Review work remains. |

File mode cannot prove that its parent module or project is secure. External dependencies are noted but not opened. COMPLETE means all T3 files in the selected scope were fully read and all T1/T2 files passed their automated scan; it does not mean every control passed or the system is certified. Runtime testing requires an authorized environment.

## Repeatable severity ratings

Every finding uses **`rscc-severity-v1`** with recorded impact classes and evidence. The helper calculates the level instead of letting the AI freely choose Medium or High. Confidence and occurrence frequency do not change severity, and optional CVSS remains separate security metadata.

| Confirmed consequence | RSCC severity |
| --- | --- |
| Minor non-blocking defect | Low |
| Bounded defect or blocked auxiliary admin action | Medium |
| Primary workflow blocked or confirmed irreversible material loss | High |
| Proven system-wide unrecoverable failure/loss | Critical |
| Improvement or verification gap without confirmed defect impact | Informational |

Security defects use a separate impact/reachability matrix in [the severity policy](references/severity-policy.md). For example, failure of admin capture/cancel/refund from an unresolved `WC_Order` reference is Medium when that is the only established consequence. High requires additional proof of a primary checkout/payment outage or actual irreversible loss. More affected handlers or High confidence do not suffice.

Stable issue identities and `<project-root>/rscc/severity_registry.json` preserve decisions across runs, even when IDs, titles, line numbers, or review mode change. An input-class/grade change must include an explicit evidence/context change or documented correction, retained in history. Old free-form grades are not silently reused as a calibrated baseline. Identical structured facts calculate identical labels; AI may still discover new evidence or issues, which must be disclosed rather than presented as an unexplained rating flip.

## Helper commands

Python 3.10+ is required for bookkeeping, plus Git CLI for folder scans that contain local `.gitignore` files. The AI performs the review; the helper only manages scope, exclusions, hashes, ledgers, and report rendering. Resolve `scripts/rscc.py` relative to the installed skill.

Folder workflow:

```text
python scripts/rscc.py inventory --root /wp --target /wp/wp-content/plugins/reepay-checkout-gateway
python scripts/rscc.py structure --module-dir /wp/rscc/reepay-checkout-gateway
python scripts/rscc.py start --module-dir /wp/rscc/reepay-checkout-gateway --utc-offset +07:00
```

The AI fills the T3 rows of `file_notes.json` before `structure` (T1/T2 rows are pre-filled). To build grep/read batches that stay inside the inventory, list paths with:

```text
python scripts/rscc.py paths --module-dir /wp/rscc/reepay-checkout-gateway --tier T3 --ext php
```
 For file mode, no structure step is needed:

```text
python scripts/rscc.py files --root /wp --file /wp/wp-content/plugins/reepay-checkout-gateway/aaa.php --file /wp/wp-content/plugins/reepay-checkout-gateway/bbb.php --utc-offset +07:00
```

Efficiency helpers (folder mode):

```text
python scripts/rscc.py scan-patterns --module-dir /wp/rscc/reepay-checkout-gateway          # reading priorities, writes pattern_scan.json
python scripts/rscc.py standards-check --run-dir <run> --write-standards                   # confirm cached standards, draft standards.md
python scripts/rscc.py standards-check --refresh                                          # deep re-verification when the cache is older than 15 days
python scripts/rscc.py asvs-matrix --run-dir <run> --level 2                               # asvs-matrix.md from asvs_features.json + asvs_overrides.json
```

The standards cache lives in `references/standards-cache.json`, the official ASVS 5.0.0 catalogue in `references/asvs-5.0.0.csv`, and the rule-based matrix defaults in `references/asvs-defaults.json`. Update them when `standards-check` reports a changed publisher version. The cache expires after `max_age_days` (15): a stale cache must be refreshed with `--refresh`, which only advances `verified_on` when every cached CWE title, cheat-sheet URL and the ASVS catalogue hash still match.

After completing `review.json`, `standards.md`, and `review-summary.md`, render and reconcile either mode with:

```text
python scripts/rscc.py finish --run-dir <returned-run-directory>
```

Use the user's actual UTC offset. Exit code 0 means valid, complete source-reading bookkeeping; 2 means valid reports with incomplete reading coverage or source drift; 1 means invalid inputs or inconsistent bookkeeping that must be corrected. More detail is in [SKILL.md](SKILL.md) and [the report contract](references/report-contract.md).

## Development checks

Run the regression suite from the repository root with Python 3.10+ and Git available:

```text
python -m unittest discover -s tests -v
```
