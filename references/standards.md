# Standards selection and evidence

Verify these official entry points on every run. The machine-readable copy of these facts is [standards-cache.json](standards-cache.json); `rscc.py standards-check` confirms its version markers and drafts `standards.md`. Keep this table and the cache consistent when a publisher changes. The observations below were checked on **2026-11-02**, not promised future versions. Follow publisher links to the actual stable/final requirement text; capture exact versions and IDs in the run's `standards.md`. Never invent an identifier or map numbering across releases from memory.

| Reference family | Official source | Baseline observed / use |
| --- | --- | --- |
| OWASP ASVS | https://asvs.owasp.org/ and https://github.com/OWASP/ASVS/releases | 5.0.0 stable. Primary verification requirements; retrieve the stable requirement catalog. |
| OWASP Top 10 | https://owasp.org/www-project-top-ten/ and https://top10.owasp.org/2025/ | 2025 published. Risk-awareness categories, not a complete verification checklist. |
| OWASP Cheat Sheet Series | https://cheatsheetseries.owasp.org/ | Living guidance; record exact relevant sheet URLs and access dates, or a publisher commit/revision where available. |
| CWE | https://cwe.mitre.org/ and https://cwe.mitre.org/data/index.html | Living weakness taxonomy; homepage announced CWE 5.0. Verify individual IDs, mapping suitability, and current release. |
| CVE and CVSS | https://www.cve.org/ and https://www.first.org/cvss/ | CVE is a vulnerability registry. CVSS 4.0 is a severity model. Consult affected-vendor advisories and published records; record score version/source. |
| OWASP WSTG | https://owasp.org/www-project-web-security-testing-guide/ | 4.2 published; 5.0 under development. Use versioned test URLs/IDs for reproducible follow-up tests. Test design is not a claim that runtime tests ran. |
| CIS Benchmarks | https://www.cisecurity.org/cis-benchmarks | Choose the benchmark for the actual OS/server/product **and version/profile**. There is no single universal CIS version for PHP code. |
| NIST SSDF | https://csrc.nist.gov/projects/ssdf and https://csrc.nist.gov/pubs/sp/800/218/final | SP 800-218 / SSDF 1.1 final observed. Verify supersession/final publication status. Assess available SDLC/CI evidence; module source cannot prove organization-wide practices. |
| PCI DSS | https://www.pcisecuritystandards.org/document_library/ | 4.0.1 featured. Determine actual payment/cardholder-data scope from evidence. External payment redirects alone do not prove all PCI obligations inapplicable. |

Also consult https://www.php.net/manual/en/security.php and https://www.php.net/supported-versions.php, the exact host framework's official security documentation, and https://getcomposer.org/doc/03-cli.md#audit as appropriate. Distinguish official manual text from user-contributed comments. Dependency assessments use in-scope manifests/lockfiles and official advisories; do not inspect excluded `vendor/`, `node_modules/`, or `build/` contents. PSR/framework coding conventions may support improvement findings, but do not substitute for security requirements.

Finding triage uses [RSCC severity policy v1](severity-policy.md). This is an explicit local policy with deterministic label calculation; it is separate from the international verification requirements and optional CVSS security scores. Record the policy version and inputs so ratings can be reproduced.

Git metadata and hosting directories `.git/`, `.github/`, `.gitlab/`, and `.gitea/` are also excluded. Do not read their workflows or configuration to fill a standards matrix; mark any dependent CI/SSDF evidence as unavailable within the selected scope.

## Define the assessment baseline

Describe the technology/version evidence, trust boundaries, authentication roles, entry points, data sensitivity, host dependencies, and observed deployment context. If the user has not specified an ASVS level, use applicable Level 1 and Level 2 requirements as the review baseline and state that choice. Evaluate the selected catalog across the target/host boundary; mark unsupported controls as NEEDS VERIFICATION or justified NOT APPLICABLE. Do not narrow the baseline to only requirements for which findings were discovered. A user-selected level takes precedence; use Level 3 only when requested or justified by system risk, documenting the scope.

In folder mode, include a control matrix for the selected ASVS catalog, one row per requirement, with versioned ID, applicability, status, evidence/files, and follow-up verification. In single-file/list mode, assess the controls relevant to those exact files and record unresolved project/host evidence; do not claim the parent module/project or full catalog was assessed. For supplementary families, list relevant requirements/tests and account for all nine families in the applicability table. For CIS/SSDF/PCI record unavailable documents/context rather than fabricate full control coverage. When an exact reference cannot be verified, write `Reference not verified` and a descriptive topic; do not output a guessed numeric ID.

## PHP review focus

Review input sources beyond request parameters: cookies, headers, uploaded content, stored database values, queues, CLI/import feeds, webhook payloads, and third-party responses. Follow them across the whole call path. Look for:

- Injection through SQL fragments/identifiers, shell commands, templates, LDAP, mail/headers, dynamic includes, and `eval`-like behavior. Binding values does not automatically protect dynamic SQL identifiers.
- HTML/attribute/JS/URL output contexts, server-side rendering, client code, and stored content. Validation and escaping have different roles.
- Authentication/reset/token lifetime, password hashing, session fixation/cookie settings, capability/role and object ownership checks, multi-tenant boundaries, and public/admin/API endpoint reachability.
- CSRF on cookie-authenticated mutations, CORS and credential handling, webhook signatures/replay, rate controls, and transactional/business-rule enforcement.
- Upload type/content/storage/execution paths, traversal/canonicalization/symlinks, archive extraction, remote URL fetching/redirects/DNS, XML entity processing, and unsafe deserialization/object injection.
- Key generation/storage, unsafe randomness, obsolete algorithms, secret exposure, sensitive logs/errors, debug configuration, and fail-open exception handling.
- Dependency constraints versus lockfile versions, custom plugin/theme code, autoloaders, build hooks, migrations/installers, deployment configuration, and test evidence.

Select only applicable checks, with reasons for exclusions. Attribute failures to the owning source/configuration and enumerate the affected files. Do not demand every control be implemented independently in every file.
