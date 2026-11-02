"""RSCC efficiency helpers: standards cache check, rule-based ASVS matrix, allow-listed pattern scan.

None of these replace the reviewer's judgement: the standards check only confirms cached version
markers, the matrix never produces PASS by itself, and the pattern scan only prioritises reading.
"""
import csv
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REFS = Path(__file__).resolve().parent.parent / "references"
STATUSES = {"PASS", "FAIL", "NEEDS VERIFICATION", "NOT APPLICABLE"}


def _load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _cell(value):
    return str(value).replace("|", "/").replace("\n", " ").strip()


# ---------------------------------------------------------------- standards cache

def _fetch(url, timeout, hops=5):
    """GET a fixed publisher URL, following up to five redirects (urllib does not follow 308)."""
    for _ in range(hops):
        req = urllib.request.Request(url, headers={"User-Agent": "rscc-standards-check/1", "Accept": "*/*"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (fixed publisher URLs from the cache)
                return resp.status, resp.read(3_000_000).decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            location = exc.headers.get("Location") if exc.code in (301, 302, 303, 307, 308) else None
            if not location:
                raise
            url = urllib.parse.urljoin(url, location)
    raise RuntimeError("too many redirects")


def _fetch_bytes(url, timeout):
    status, _ = None, None
    req = urllib.request.Request(url, headers={"User-Agent": "rscc-standards-check/1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (fixed publisher URL; urllib follows the 302 asset redirect)
        return resp.read(20_000_000)


def _version_key(text):
    return tuple(int(p) for p in re.findall(r"\d+", text))


def check_family(family, timeout=20, fetch=_fetch):
    check = family.get("check", {})
    kind = check.get("type")
    try:
        if kind == "github_release":
            _, body = fetch(f"https://api.github.com/repos/{check['repo']}/releases?per_page=15", timeout)
            releases = [r for r in json.loads(body) if not r.get("prerelease") and not r.get("draft") and r.get("tag_name") != "latest" and "bleeding" not in (r.get("name") or "").lower()]
            newest = max(releases, key=lambda r: r.get("published_at") or "")["tag_name"] if releases else ""
            return ("current" if newest == check["expect_tag"] else "changed"), f"latest stable tag {newest or 'not found'}"
        if kind in {"regex_max", "regex_contains"}:
            _, body = fetch(check["url"], timeout)
            found = re.findall(check["pattern"], body)
            if kind == "regex_contains":
                return ("current" if found else "changed"), ("marker present" if found else "marker not found")
            if not found:
                return "unverified", "version marker not found on page"
            newest = max(found, key=_version_key)
            return ("current" if newest == check["expect"] else "changed"), f"highest marker {newest}"
        if kind == "reachable":
            status, _ = fetch(check["url"], timeout)
            return ("current" if status == 200 else "unverified"), f"HTTP {status}"
    except Exception as exc:  # network failures must not stop the review
        return "unverified", f"{type(exc).__name__}: {str(exc)[:80]}"
    return "unverified", "no check defined"


def deep_refresh(cache, timeout=20, fetch=_fetch, fetch_bytes=_fetch_bytes):
    """Re-verify every cached fact that the light check does not cover. Returns a list of problems."""
    import hashlib
    problems = []
    for cwe_id, title in cache["families"]["cwe"].get("titles", {}).items():
        try:
            _, body = fetch(f"https://cwe.mitre.org/data/definitions/{cwe_id}.html", timeout)
            match = re.search(r"<title>\s*CWE\s*-\s*CWE-" + cwe_id + r":\s*(.*?)\s*\((\d+\.\d+)\)\s*</title>", body, re.S)
            if not match:
                problems.append(f"CWE-{cwe_id}: title not found")
            elif re.sub(r"\s+", " ", match.group(1)).strip() != title:
                problems.append(f"CWE-{cwe_id}: title changed to '{match.group(1).strip()}'")
        except Exception as exc:
            problems.append(f"CWE-{cwe_id}: {type(exc).__name__}")
    for name, url in cache["families"]["cheatsheets"].get("sheets", {}).items():
        try:
            status, _ = fetch(url, timeout)
            if status != 200:
                problems.append(f"Cheat sheet '{name}': HTTP {status}")
        except Exception as exc:
            problems.append(f"Cheat sheet '{name}': {type(exc).__name__}")
    asvs = cache["families"]["asvs"]
    if asvs.get("catalog_asset_url"):
        try:
            digest = hashlib.sha256(fetch_bytes(asvs["catalog_asset_url"], timeout)).hexdigest()
            if digest != asvs["catalog_sha256"]:
                problems.append("ASVS catalogue asset hash differs from the cached catalogue")
        except Exception as exc:
            problems.append(f"ASVS catalogue asset: {type(exc).__name__}")
    return problems


def cache_age_days(cache, today=None):
    today = today or datetime.now(timezone.utc).date()
    return (today - datetime.strptime(cache["verified_on"], "%Y-%m-%d").date()).days


def standards_check(args, fetch=_fetch, fetch_bytes=_fetch_bytes, today=None):
    import hashlib
    cache_path = REFS / "standards-cache.json"
    cache = _load(cache_path)
    max_age = getattr(args, "max_age_days", None) or cache.get("max_age_days", 15)
    age = cache_age_days(cache, today)
    results = {}
    for key, fam in cache["families"].items():
        state, detail = ("unverified", "offline mode") if args.offline else check_family(fam, args.timeout, fetch)
        results[key] = {"name": fam["name"], "cached_version": fam["version"], "state": state, "detail": detail}
    catalog = REFS / cache["families"]["asvs"]["catalog_file"]
    digest = hashlib.sha256(catalog.read_bytes()).hexdigest() if catalog.exists() else ""
    light_ok = all(r["state"] == "current" for r in results.values()) and digest == cache["families"]["asvs"]["catalog_sha256"]
    report = {"checked_at": datetime.now(timezone.utc).isoformat(), "cache_verified_on": cache["verified_on"], "cache_age_days": age, "max_age_days": max_age,
              "stale": age > max_age, "catalog_intact": digest == cache["families"]["asvs"]["catalog_sha256"], "results": results}
    if getattr(args, "refresh", False) and not args.offline:
        problems = deep_refresh(cache, args.timeout, fetch, fetch_bytes)
        refreshed = light_ok and not problems
        if refreshed:
            cache["verified_on"] = (today or datetime.now(timezone.utc).date()).isoformat()
            tmp = cache_path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(cache, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            tmp.replace(cache_path)
            report.update(cache_verified_on=cache["verified_on"], cache_age_days=0, stale=False)
        report["deep_refresh"] = {"performed": True, "updated_cache": refreshed, "problems": problems + ([] if light_ok else ["light check not fully current"])}
    if not light_ok:
        report["action"] = "Some markers changed or could not be verified: browse those publishers, update standards-cache.json (versions, URLs, catalogue and hash, verified_on), and state the limitation in standards.md."
    elif report["stale"]:
        report["action"] = f"Cache is {age} days old (limit {max_age}). Run 'rscc.py standards-check --refresh' before relying on it; if the refresh reports problems, browse those publishers and update the cache by hand."
    else:
        report["action"] = "Cache current: render standards.md from it."
    if args.run_dir:
        run = Path(args.run_dir)
        (run / "standards-check.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        if args.write_standards:
            (run / "standards.md").write_text(render_standards(cache, report), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


def render_standards(cache, report):
    today = report["checked_at"][:10]
    lines = ["# Standards verified for this run", "",
             f"Checked on {today} with `rscc.py standards-check` against the skill's cache (last fully verified {cache['verified_on']}). "
             "'current' means the publisher's version marker still matches the cache; 'changed' or 'unverified' entries must be browsed and explained below before relying on them.", "",
             "| Family | Version | Status | Sources | Check result | Limitations |", "| --- | --- | --- | --- | --- | --- |"]
    for key, fam in cache["families"].items():
        res = report["results"][key]
        lines.append(f"| {_cell(fam['name'])} | {_cell(fam['version'])} | {_cell(fam['status'])} | {_cell(' ; '.join(fam['urls']))} | {_cell(res['state'] + ': ' + res['detail'])} | {_cell(fam.get('limitations', ''))} |")
    lines += ["", f"ASVS catalogue file intact: {report['catalog_intact']}. Cache age: {report['cache_age_days']} days (limit {report['max_age_days']}).", ""]
    if report["stale"]:
        lines += [f"- TODO: complete before finish. The standards cache is stale ({report['cache_age_days']} days); run 'rscc.py standards-check --refresh' or verify every family manually and record it here.", ""]
    lines += [
              "Reviewer additions (applicability per family, browsing results for changed/unverified entries):", "", "- TODO: complete before finish.", ""]
    return "\n".join(lines)


# ---------------------------------------------------------------- ASVS matrix

def _matches(req_id, rule_ids):
    return any(req_id == r or req_id.startswith(r + ".") for r in rule_ids)


def asvs_matrix(args):
    defaults = _load(REFS / "asvs-defaults.json")
    rows = list(csv.DictReader((REFS / defaults["catalog"]).open(encoding="utf-8-sig")))
    levels = {str(i) for i in range(1, int(args.level) + 1)}
    rows = [r for r in rows if r["L"] in levels]
    known = {r["req_id"] for r in rows}
    run = Path(args.run_dir)
    features = _load(run / "asvs_features.json") if (run / "asvs_features.json").exists() else {}
    overrides = _load(run / "asvs_overrides.json") if (run / "asvs_overrides.json").exists() else {}
    unknown_features = set(features) - set(defaults["features"])
    if unknown_features:
        raise ValueError(f"Unknown feature keys in asvs_features.json: {sorted(unknown_features)}")
    for rid, value in overrides.items():
        if rid not in known:
            raise ValueError(f"Override for unknown or out-of-level requirement: {rid}")
        if not (isinstance(value, list) and len(value) >= 2 and value[0] in STATUSES and str(value[1]).strip()):
            raise ValueError(f"Override {rid} must be [status, evidence, follow_up?] with a valid status and evidence")
    out, counts = [], {}
    for r in rows:
        rid = r["req_id"]
        if rid in overrides:
            status, evidence = overrides[rid][0], overrides[rid][1]
            follow = overrides[rid][2] if len(overrides[rid]) > 2 else "-"
            source = "reviewer"
        else:
            status, evidence, follow, source = defaults["default"]["status"], defaults["default"]["reason"], defaults["default"]["follow_up"], "default"
            for name, rule in defaults["features"].items():
                if features.get(name) is False and _matches(rid, rule["ids"]):
                    status, evidence, follow, source = "NOT APPLICABLE", rule["reason"], "-", f"feature:{name}"
                    break
            else:
                for group in ("memory_safe_language", "host", "documentation"):
                    rule = defaults[group]
                    if _matches(rid, rule["ids"]):
                        status = "NOT APPLICABLE" if group == "memory_safe_language" else "NEEDS VERIFICATION"
                        evidence, follow, source = rule["reason"], "-" if group == "memory_safe_language" else "Verify outside the source scope.", group
                        break
        counts[status] = counts.get(status, 0) + 1
        desc = r["req_description"]
        desc = desc[:105] + ("..." if len(desc) > 105 else "")
        out.append(f"| {rid} | {r['L']} | {_cell(desc)} | {status} | {_cell(evidence)} | {_cell(follow)} | {source} |")
    header = [f"# ASVS 5.0.0 requirement matrix (L1-L{args.level})", "",
              "Generated by `rscc.py asvs-matrix` from the official catalogue, the reviewer's feature declarations (asvs_features.json) and overrides (asvs_overrides.json). "
              "Rows marked 'default', 'host' or 'documentation' were not individually evidenced; only 'reviewer' rows carry review evidence.", "",
              "Totals: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) + ".", "",
              "| ID | L | Requirement (abridged) | Status | Evidence / files | Follow-up | Basis |", "| --- | --- | --- | --- | --- | --- | --- |"]
    (run / "asvs-matrix.md").write_text("\n".join(header + out) + "\n", encoding="utf-8")
    print(json.dumps({"matrix": str(run / "asvs-matrix.md"), "rows": len(out), "counts": counts}))
    return 0


# ---------------------------------------------------------------- pattern scan

PATTERNS = {
    "input_sources": r"\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b|php://input|\$request\[|get_query_var\(|->get_param\(",
    "output_sinks": r"\becho\b|\bprint\b|<\?=|\bprintf\s*\(|\.html\(|\.append\(|innerHTML|dangerouslySetInnerHTML|<%=",
    "escaping_and_sanitising": r"\besc_(html|attr|url|textarea|js|sql)\w*\(|wp_kses\w*\(|sanitize_\w+\(|absint\(|intval\(|wc_clean\(",
    "authorization_and_csrf": r"current_user_can\(|user_can\(|wp_verify_nonce\(|check_ajax_referer\(|check_admin_referer\(|permission_callback|is_user_logged_in\(",
    "dangerous_calls": r"\b(eval|assert|create_function|exec|shell_exec|system|passthru|popen|proc_open|unserialize|maybe_unserialize|extract|call_user_func(_array)?)\s*\(|\$wpdb->(query|get_\w+)\(|\b(include|require)(_once)?\s*\(?\s*\$",
    "state_changes": r"update_option\(|delete_option\(|update_(post|user)_meta\(|wp_insert_\w+\(|wp_update_\w+\(|wp_delete_\w+\(|set_role\(|add_role\(|wp_create_user\(|->save\(\)",
    "outbound_and_secrets": r"wp_remote_\w+\(|curl_\w+\(|file_get_contents\s*\(\s*['\"]https?:|private_?key|api_?key|secret|password",
    "entry_points": r"add_action\(\s*['\"](wp_ajax_\w*|admin_post_\w*|rest_api_init|template_redirect|init|wp)['\"]|register_rest_route\(|add_(sub)?menu_page\(",
}


def scan_patterns(args, inv, triage_rows, module):
    target = Path(inv["target"])
    compiled = {name: re.compile(p, re.I) for name, p in PATTERNS.items()}
    hits = {name: [] for name in PATTERNS}
    per_file = {}
    for row in inv["entries"]:
        if row["kind"] != "file" or row["error"]:
            continue
        if triage_rows.get(row["path"], {}).get("tier", "T3") != "T3":
            continue
        try:
            text = (target / row["path"]).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            for name, rx in compiled.items():
                if rx.search(line):
                    hits[name].append(f"{row['path']}:{number}: {line.strip()[:140]}")
                    per_file.setdefault(row["path"], {}).setdefault(name, 0)
                    per_file[row["path"]][name] += 1
    ranking = sorted(per_file.items(), key=lambda kv: -(kv[1].get("input_sources", 0) * 3 + kv[1].get("dangerous_calls", 0) * 3 + kv[1].get("state_changes", 0) * 2 + kv[1].get("output_sinks", 0)))
    report = {"policy": "prioritisation only; every T3 file must still be read in full", "counts": {k: len(v) for k, v in hits.items()}, "priority_order": [p for p, _ in ranking], "per_file": per_file, "hits": hits}
    (module / "pattern_scan.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"pattern_scan": str(module / "pattern_scan.json"), "counts": report["counts"], "read_first": report["priority_order"][: args.top]}, indent=2))
    return 0
