"""Versioned RSCC severity decisions; inputs require evidence-based human/AI review."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

POLICY = "rscc-severity-v1"
FUNCTIONAL = {
    "minor": "Low",
    "bounded": "Medium",
    "auxiliary-blocked": "Medium",
    "core-blocked": "High",
    "irreversible-loss": "High",
    "system-wide-loss": "Critical",
}
SECURITY = {
    "limited": {"privileged": "Low", "authenticated": "Medium", "unauthenticated": "Medium"},
    "sensitive": {"privileged": "Medium", "authenticated": "High", "unauthenticated": "High"},
    "system-wide": {"privileged": "High", "authenticated": "High", "unauthenticated": "Critical"},
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def text_field(row, name):
    value = row.get(name)
    require(isinstance(value, str) and value.strip(), f"Severity policy requires {name}")
    return value.strip()


def assess(finding):
    assessment = finding.get("severity_assessment", {})
    require(assessment.get("policy") == POLICY, f"Severity policy requires {POLICY}; reassess legacy findings explicitly")
    kind = text_field(assessment, "kind")
    impact = text_field(assessment, "impact")
    text_field(assessment, "basis")
    assessment["context_id"] = text_field(assessment, "context_id")
    category = finding["category"]
    expected_kind = {"security": "security", "bug": "functional", "improve": "advisory", "verification-gap": "advisory"}.get(category)
    require(expected_kind is None or kind == expected_kind, f"Category {category} requires severity kind {expected_kind}")
    facts = {"kind": kind, "impact": impact}
    if kind == "functional":
        require(impact in FUNCTIONAL, "Invalid functional impact class")
        severity = FUNCTIONAL[impact]
    elif kind == "security":
        reachability = text_field(assessment, "reachability")
        require(impact in SECURITY and reachability in SECURITY[impact], "Security impact/reachability must be established; otherwise use a verification gap")
        facts["reachability"] = reachability
        severity = SECURITY[impact][reachability]
    elif kind == "advisory":
        require(impact == "none", "Advisory impact must be none; possible impact belongs in the verification-gap narrative")
        severity = "Informational"
    else:
        raise ValueError("Invalid severity kind")
    supplied = finding.get("severity")
    require(supplied is None or supplied == severity, f"Severity mismatch for {finding['id']}: expected {severity} under {POLICY} ({kind}/{impact})")
    finding["severity"] = severity
    return facts


def decision(finding, inv):
    facts = assess(finding)
    identity = finding.get("identity", {})
    owner = text_field(identity, "path")
    symbol = text_field(identity, "symbol")
    mechanism = text_field(identity, "mechanism")
    require(owner in {loc["path"] for loc in finding["locations"]}, "Severity identity path must be an affected file")
    root = Path(inv["root"])
    base = root if inv.get("mode") == "files" else Path(inv["target"])

    def canonical(path):
        require(path in {r["path"] for r in inv["entries"]}, "Severity evidence must be an inventoried file")
        absolute = base / path
        require(absolute.is_relative_to(root) and ".." not in Path(path).parts, "Invalid severity identity path")
        return absolute.relative_to(root).as_posix()

    canonical_identity = {"path": canonical(owner), "symbol": symbol, "mechanism": mechanism}
    encoded = json.dumps(canonical_identity, sort_keys=True, separators=(",", ":")).encode()
    key = hashlib.sha256(encoded).hexdigest()
    finding["stable_key"] = key
    hashes = {row["path"]: row["sha256"] for row in inv["entries"]}
    evidence = {canonical(loc["path"]): hashes[loc["path"]] for loc in finding["locations"]}
    return key, {"identity": canonical_identity, "policy": POLICY, "facts": facts, "context_id": finding["severity_assessment"]["context_id"], "evidence_files": evidence, "severity": finding["severity"], "basis": finding["severity_assessment"]["basis"]}


def reconcile(findings, inv, registry_path, persist):
    """Reject silent changes; save a baseline only for a stable, complete source run."""
    decisions = [decision(finding, inv) for finding in findings]
    require(len({key for key, _ in decisions}) == len(decisions), "Duplicate stable finding identities; merge the same root cause")
    if not decisions:
        return
    lock = registry_path.with_suffix(".lock")
    try:
        handle = lock.open("x", encoding="utf-8")
    except FileExistsError:
        raise ValueError("Severity registry is busy; retry finish after the other run completes")
    temporary = registry_path.with_name(registry_path.name + "." + str(uuid4()) + ".tmp")
    try:
        handle.close()
        data = json.loads(registry_path.read_text(encoding="utf-8")) if registry_path.exists() else {"schema_version": 1, "records": {}, "history": []}
        require(data.get("schema_version") == 1, "Unsupported severity registry schema")
        for finding, (key, record) in zip(findings, decisions):
            previous = data["records"].get(key)
            changed = previous and (previous["facts"] != record["facts"] or previous["severity"] != record["severity"] or previous["policy"] != record["policy"])
            if changed:
                change = finding.get("severity_change", {})
                require(change.get("previous") == previous["severity"] and isinstance(change.get("reason"), str) and change["reason"].strip() and isinstance(change.get("evidence"), list) and change["evidence"] and all(isinstance(e, str) and e.strip() for e in change["evidence"]), "Severity classification changed without a documented previous level, reason, and concrete evidence")
                change_type = change.get("type")
                valid = ((change_type == "evidence-change" and previous["evidence_files"] != record["evidence_files"])
                         or (change_type == "context-change" and previous["context_id"] != record["context_id"])
                         or (change_type == "policy-change" and previous["policy"] != record["policy"])
                         or change_type == "correction")
                require(valid, "Unchanged severity evidence/context cannot be reclassified silently; document a supported correction or actual change")
                data["history"].append({"stable_key": key, "previous": previous, "replacement": record, "change": change, "recorded_at": datetime.now(timezone.utc).isoformat()})
            data["records"][key] = record
        if persist:
            temporary.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            temporary.replace(registry_path)
    finally:
        if temporary.exists():
            temporary.unlink()
        lock.unlink()
