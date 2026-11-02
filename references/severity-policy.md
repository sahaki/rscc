# RSCC severity policy v1

Policy identifier: **`rscc-severity-v1`**. This is a versioned RSCC triage policy, not an OWASP rule, CVSS formula, or certification. It applies equally to folder, single-file, and file-list reviews.

## Required order

1. Establish the actual failure/exploit path and bounded consequence from selected source and declared context. Missing decisive evidence is a `verification-gap`, not a confirmed vulnerability.
2. Choose `kind`, the narrowly evidenced impact class, and (for security) the established actor/reachability. Record evidence in `basis`; do not invent wider business effects.
3. Apply the tables below. The helper calculates the label and rejects a supplied label that disagrees. Never assign the label first and invent impact facts to justify it.
4. Keep confidence, occurrence frequency, remediation priority, CVSS, and severity separate. More affected lines/functions, an alarming title, payment terminology, or High confidence cannot by themselves increase severity. An always-failing auxiliary action is still an auxiliary action.
5. Match the issue to its stable identity and compare the stored decision. Reuse the same classes for the same evidence/context. Document actual changes or corrections rather than silently changing the classification.

## Functional defects

Use `kind: functional` for `bug`; an `issue` may use this kind when it is an evidenced functional failure. Select the first clearly supported consequence class; prefer the narrower class when wider impact is unproven.

| Impact class | Severity | Evidence needed / boundary |
| --- | --- | --- |
| `minor` | Low | Cosmetic, diagnostic, or non-blocking defect; no incorrect financial/persistent result or blocked normal workflow. |
| `bounded` | Medium | Incorrect or failed bounded behavior, reversible/localized state issue, or conditional business operation failure; no proven core-flow outage or irreversible loss. |
| `auxiliary-blocked` | Medium | An administrative/support/optional operation cannot complete. Default examples: manual admin capture/cancel/refund, report export, optional settings action. Always failing and several handlers sharing one cause do not raise the level. |
| `core-blocked` | High | A primary end-user/service workflow is proven unable to complete under its documented supported conditions: e.g. checkout/payment completion, required authentication, or the service's principal operation. Trace the blocked primary path; a helper name or admin payment action alone is insufficient. |
| `irreversible-loss` | High | Confirmed incorrect charges/refunds, unrecoverable material data corruption, or permanent loss. A possible future loss or difficulty using an admin action is not sufficient. |
| `system-wide-loss` | Critical | Confirmed broad, unrecoverable loss or complete failure of the essential system across its normal users/tenants, with scope and recovery limits evidenced. Not merely a whole class/module or several methods failing. |

Default context ID is `source-only`. If the user supplies a verified business profile making an otherwise auxiliary action the **only essential primary workflow**, record a stable, explicit context ID and the evidence; only then can `core-blocked` apply. Do not infer a business profile from company/domain/module names. Workarounds may be mentioned only when evidenced; lack of a known workaround does not automatically turn an auxiliary defect into a core outage.

### Calibration for the user's example

Root cause: an unresolved `WC_Order` reference in namespaced admin AJAX capture/cancel/refund handlers. If selected source establishes only that these admin operations fail, classify **`functional / auxiliary-blocked -> Medium`**, regardless of "always", "payment", confidence, issue ordering, or the number of handlers. This is a policy calibration, not a verified audit of the user's unseen repository.

Upgrade to High only when additional evidence establishes a primary checkout/payment workflow outage (`core-blocked`) or actual irreversible loss. Preserve that additional evidence and the reason for the change. Do not fabricate primary-flow impact to make the finding sound more serious.

## Confirmed security defects

Use `kind: security` for category `security`. A complete source-level trace may establish a path; runtime testing is not automatically required to confirm every code defect, but missing route/guard/ownership evidence must not be guessed. Record authenticated roles, prerequisites, trust boundary, protected asset, and consequence. Unknown reachability or a merely hypothetical effect must be a verification gap instead.

| Impact class | Privileged actor | Authenticated non-privileged actor | Unauthenticated actor |
| --- | --- | --- | --- |
| `limited` | Low | Medium | Medium |
| `sensitive` | Medium | High | High |
| `system-wide` | High | High | Critical |

Reachability values: `privileged`, `authenticated`, `unauthenticated`. Choose the **least-privileged established actor**, not a hypothetical caller. `privileged` means a highly trusted admin/operator role is actually required; a normal logged-in customer is `authenticated`.

- `limited`: bounded, reversible or non-sensitive effect; no demonstrated cross-user sensitive-data access, substantial privilege escalation, or broad compromise.
- `sensitive`: demonstrated cross-user/tenant sensitive access or modification, account takeover, substantial unauthorized privilege, or material integrity/availability compromise with bounded scope.
- `system-wide`: demonstrated full service/host takeover or broad critical confidentiality/integrity/availability compromise across the essential system. Executing a dangerous-looking function, touching many files, or discovering an unverified sink is not enough.

CVSS may be reported separately for confirmed security vulnerabilities with a verified vector/score/source. Preserve published scores and versions; do not use them as functional-bug scores or silently substitute them for the RSCC table. See [FIRST's specification](https://www.first.org/cvss/v4.0/specification-document) and [user guide](https://www.first.org/cvss/v4.0/user-guide). The single `Severity` column always means **RSCC severity under the recorded policy**.

## Advisory findings

`improve` and `verification-gap` use **`kind: advisory`, `impact: none` -> Informational**. Explain a potential consequence and what evidence/test would resolve it in the narrative; do not make it a confirmed High vulnerability. Other categories must explicitly select one of the three kinds and satisfy that kind's evidence rules. Do not down-classify an established bug as advisory to avoid an evidenced failure.

## Structured finding fields

```json
{
  "identity": {
    "path": "includes/Admin/Ajax.php",
    "symbol": "Reepay\\Checkout\\Admin\\Ajax",
    "mechanism": "unresolved-class:WC_Order"
  },
  "severity_assessment": {
    "policy": "rscc-severity-v1",
    "kind": "functional",
    "impact": "auxiliary-blocked",
    "context_id": "source-only",
    "basis": "Selected admin handlers reject the order before capture/cancel/refund; no primary checkout outage or permanent loss is established."
  }
}
```

For security, add `reachability`. `severity` may be omitted for the helper to calculate, or supplied only if it matches the table. Confidence remains a separate field.

`identity.path` must name an affected inventoried file, using the current mode's path base. `symbol` is the exact fully qualified owning class/function/route. A missing class import or namespace-level resolution defect shared by class methods belongs to the fully qualified **class**, not a changing choice of handler. A defect confined to one function/method belongs to that exact qualified callable; use `<file>` only when no stable named owner exists. For unresolved class references, use the canonical mechanism `unresolved-class:<exact referenced short name>` (e.g. `unresolved-class:WC_Order`), not alternate tags such as `missing-import` on a later run. Other mechanisms must likewise reuse the prior stable tag. The helper converts paths to project-relative form and hashes these identity fields. IDs, titles, line numbers, severity and confidence are **not** part of the key. Merge repeated handlers of the same root cause under one owning symbol/identity instead of creating new identities to evade consistency checks.

## Cross-run decision registry

Complete, stable-source runs with findings update `<project-root>/rscc/severity_registry.json`. The registry stores identity, policy, structured facts, selected evidence-file hashes, context ID, severity, and correction history. Partial/drifting runs do not establish a new baseline. Read this output artifact to identify previous matching root causes; never use it as permission to read unselected source files.

The same identity and facts always calculate the same severity. If structured classes or severity differ from a stored decision, `finish` refuses a silent change. To make a supported change, include:

```json
{
  "severity_change": {
    "previous": "Medium",
    "type": "context-change",
    "reason": "A newly supplied business profile establishes that these handlers are the sole supported primary payment-completion path.",
    "evidence": ["User-provided profile merchant-payments-v2 and the selected handler/control-flow evidence."]
  }
}
```

Allowed change types: `evidence-change` (affected evidence hashes differ, including an actual change of selected evidence scope), `context-change` (stable context ID differs), `policy-change` (policy version differs), or `correction` (specific evidence explains why the previous interpretation was wrong). A correction is permitted to avoid preserving a known error, but it must be explicit and auditable. A reworded title, different finding ID, different confidence, or "this feels High" is not change evidence. Do not invent a new context ID or mechanism to bypass the registry. Genuine corrections are reviewed against source evidence, not prohibited merely for consistency.

Old free-form report labels are not a calibrated baseline. Preserve historical reports; on the first run using v1, assess with this policy and establish a new versioned decision. Do not pretend to retroactively validate old grades.

Deterministic label calculation does not guarantee identical AI finding discovery or interpretation. The helper enforces the tables, records the input facts, and blocks silent classification changes; the reviewer remains responsible for the truth and completeness of those facts.
