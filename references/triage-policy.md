# RSCC inspection tiers (policy `rscc-triage-v1`)

Folder mode classifies every inventoried file into an inspection tier during `inventory`. The result is saved in `triage.json` next to `inventory.json` and copied into each run. File mode (explicit file lists) does not use tiers: every selected file is read in full.

The classifier is conservative. When in doubt it chooses T3 (full read). It never lowers a file to T1/T2 based on its extension alone.

## Tiers

| Tier | Inspection mode | What the AI does | Typical files |
| --- | --- | --- | --- |
| T1 | `metadata` | Nothing beyond accepting the helper's record (path, size, hash, magic-byte check, code-marker scan). | Images, fonts, media, PDF/Office documents, compiled `.mo`, `.map` source maps, `.DS_Store`, `Thumbs.db` |
| T2 | `scanned` | Accept the scripted scan. For lockfiles, run the ecosystem audit and record its result in the seeded check. | CSS/SCSS/LESS, `.po/.pot`, `.md/.txt`, plain `.json` (not `package.json`/`composer.json`), `.svg`, ignore/editor config, lockfiles |
| T3 | `full` | Read every line (split into chunks if large) and assess controls. | Everything else, and every promoted file |

## Always T3 (never tiered down)

- PHP of any kind (`.php .phtml .inc` and templates), even when it looks like a passive template. To save effort, grep the file for output and input sinks first and read those parts with most attention, but read the whole file.
- JavaScript/TypeScript source (`.js .jsx .ts .tsx .mjs .cjs`), including build configs.
- `package.json`, `composer.json` (install/run scripts), `.npmrc`, `.env*`, `.htaccess`, `.user.ini`, `web.config`, server configs.
- SQL, shell, Python, PowerShell, batch scripts; YAML/CI/Docker files.
- Archives (`.zip .tar .gz .phar`): list and assess the contents; flag their presence in a web root.
- Files with an unknown extension.

## Promotion guards (T1/T2 -> T3)

The helper promotes a file to T3 when any of these applies:

- The magic bytes do not match the extension (for example a `.png` that is really PHP).
- A code marker is found: `<?php`, `<?=`, `<script`, `javascript:`, inline `on*=` handlers, CSS `expression(`, remote `@import url(http...)`, `eval(`.
- A possible secret is found (assignment of a long token to `api_key/secret/password/token/private key`, PEM private key header, AWS access key id).
- A text asset contains binary bytes, a `.json` file does not parse, or the file exceeds the scan limit (2 MB text, 8 MB binary).
- A lockfile has non-registry, git, `file:` or plain-HTTP sources, or entries without integrity hashes.
- The file was unreadable during triage.

## Seeded ledger outcomes

- **T1 and T2 non-lockfiles:** `file_notes.json` is pre-filled (`source_related: false`, `inspected: true`, generic purpose/behaviour text) and `review.json` is pre-seeded as `NOT APPLICABLE`, `read_complete: true`, `inspection_mode` = `metadata` or `scanned`. The AI may overwrite these notes with richer text.
- **Lockfiles:** `source_related: true`, seeded as `NEEDS VERIFICATION` with a placeholder check. The AI runs `npm audit --package-lock-only --ignore-scripts` / `composer audit --locked` (no installs, no scripts) on a copy, and replaces the check with the real result.
- **T3:** left blank for the AI as before.

## Rules for the AI

1. You may always read a T1/T2 file in full and set `inspection_mode: "full"`; you may never record a T3 file as `scanned` or `metadata`. `finish` rejects that.
2. If anything in a T2 file looks relevant during other work (a link to it from PHP, a translation string with markup echoed raw), read it in full and update its row.
3. Report the tier counts and the triage policy in `review-summary.md`. `coverage.md` shows them automatically.
4. Use `rscc.py inventory --no-triage` when the user asks for an exhaustive full read; the run is then recorded with `triage_policy: disabled`.
5. COMPLETE coverage under triage means: every T3 file was fully read and every T1/T2 file passed its automated scan. State this wording in the summary.
