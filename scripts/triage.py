"""Inspection-tier classification for RSCC (policy: references/triage-policy.md).

Tiers
  T1  metadata only: binary/passive assets whose bytes match their extension and contain no code markers.
  T2  scripted scan: text assets (CSS, translations, docs, lockfiles, plain JSON/config) with no code or secret patterns.
  T3  full read: everything else, and anything promoted because a guard tripped.

The classifier is deliberately conservative: any doubt promotes a file to T3. PHP is always T3.
"""
import json
import re
from pathlib import Path

POLICY = "rscc-triage-v1"

T1_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tif", ".tiff",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".webm", ".mp3", ".wav", ".ogg", ".mov", ".avi", ".flv", ".wmv",
    ".pdf", ".docx", ".xlsx", ".pptx", ".mo", ".map",
}
T1_NAMES = {".ds_store", "thumbs.db"}
MAGIC = {
    ".png": [b"\x89PNG"], ".jpg": [b"\xff\xd8\xff"], ".jpeg": [b"\xff\xd8\xff"], ".gif": [b"GIF8"],
    ".webp": [b"RIFF"], ".ico": [b"\x00\x00\x01\x00"], ".bmp": [b"BM"], ".tif": [b"II*\x00", b"MM\x00*"], ".tiff": [b"II*\x00", b"MM\x00*"],
    ".pdf": [b"%PDF"], ".woff": [b"wOFF"], ".woff2": [b"wOF2"], ".ttf": [b"\x00\x01\x00\x00", b"true"], ".otf": [b"OTTO"],
    ".docx": [b"PK"], ".xlsx": [b"PK"], ".pptx": [b"PK"], ".mo": [b"\xde\x12\x04\x95", b"\x95\x04\x12\xde"],
}
T2_EXT = {
    ".css", ".scss", ".sass", ".less", ".po", ".pot", ".md", ".txt", ".svg", ".json",
    ".gitignore", ".gitattributes", ".editorconfig", ".prettierrc", ".prettierignore", ".eslintignore",
}
T2_NAMES = {".gitignore", ".gitattributes", ".editorconfig", ".prettierrc", ".prettierignore", ".eslintignore", "license", "licence", "changelog", "readme"}
LOCK_NAMES = {"package-lock.json", "composer.lock", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json"}
ALWAYS_FULL_NAMES = {"package.json", "composer.json", ".npmrc", ".htaccess", ".user.ini", "web.config", ".env"}
REGISTRY_OK = {"registry.npmjs.org", "registry.yarnpkg.com", "api.github.com", "github.com", "codeload.github.com"}
T2_TEXT_LIMIT = 2 * 1024 * 1024
BINARY_SCAN_LIMIT = 8 * 1024 * 1024

CODE = re.compile(rb"(?i)<\?php|<\?=|<script|javascript:|\bon(?:error|load|click|mouseover|focus)\s*=|expression\s*\(|@import\s+url\(\s*['\"]?https?:|\beval\s*\(")
SECRET = re.compile(rb"(?i)(?:api[_-]?key|secret|passwd|password|token|private[_ -]?key)['\"]?\s*[:=]\s*['\"][A-Za-z0-9/+_\-]{12,}['\"]|-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}")


def _read(path, limit):
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    return data[:limit], len(data) > limit


def _lock_facts(path, name):
    """Return (facts, promote_reason or '')."""
    raw = path.read_bytes()
    facts = {"kind": name}
    hosts = {}
    if name in {"package-lock.json", "npm-shrinkwrap.json", "composer.lock"}:
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return facts, "lockfile is not valid JSON"
        urls, missing, scripts, count = [], 0, [], 0
        if name == "composer.lock":
            for group in ("packages", "packages-dev"):
                for pkg in doc.get(group, []):
                    count += 1
                    url = (pkg.get("dist") or {}).get("url") or (pkg.get("source") or {}).get("url") or ""
                    urls.append(url)
                    if not (pkg.get("dist") or {}).get("shasum") and not pkg.get("source"):
                        missing += 1
        else:
            entries = doc.get("packages") or {}
            if entries:
                items = [(k, v) for k, v in entries.items() if k]
            else:
                items = list((doc.get("dependencies") or {}).items())
            for key, pkg in items:
                count += 1
                if isinstance(pkg, dict):
                    urls.append(pkg.get("resolved", "") or "")
                    if pkg.get("resolved") and not pkg.get("integrity"):
                        missing += 1
                    if pkg.get("hasInstallScript"):
                        scripts.append(key)
        bad = []
        for url in urls:
            match = re.match(r"^(?:git\+)?(https?|ssh|git|file)://([^/:@]+@)?([^/:]+)", url) if url else None
            host = match.group(3) if match else ""
            scheme = match.group(1) if match else ""
            if host:
                hosts[host] = hosts.get(host, 0) + 1
            if url and (url.startswith(("git", "file:")) or scheme in {"http", "git", "ssh", "file"} or (host and host not in REGISTRY_OK)):
                bad.append(url[:80])
        facts.update(entries=count, hosts=hosts, missing_integrity=missing, install_script_packages=scripts[:20], non_registry=bad[:5])
        if bad:
            return facts, "non-registry, git, file or plain-http dependency source"
        if missing:
            return facts, "dependencies without integrity hashes"
        return facts, ""
    text = raw.decode("utf-8", "replace")
    found = re.findall(r"https?://([^/\s\"']+)", text)
    for host in found:
        hosts[host] = hosts.get(host, 0) + 1
    facts.update(hosts=hosts)
    if any(h not in REGISTRY_OK for h in hosts):
        return facts, "dependency source outside the known registries"
    return facts, ""


def classify(path, rel, size):
    """Classify one regular file. Returns {tier, mode, reason, facts}."""
    name = path.name.lower()
    ext = path.suffix.lower()
    base = {"tier": "T3", "mode": "full", "reason": "default: full read", "facts": {}}
    if name in ALWAYS_FULL_NAMES or name.startswith(".env"):
        base["reason"] = "executable or security-relevant configuration"
        return base
    if name in LOCK_NAMES:
        facts, promote = _lock_facts(path, name)
        base["facts"] = facts
        if promote:
            base["reason"] = "lockfile guard tripped: " + promote
            return base
        return {"tier": "T2", "mode": "scanned", "reason": "lockfile: structure parsed; run the ecosystem audit (npm audit --package-lock-only --ignore-scripts / composer audit --locked) and record the result", "facts": facts, "lockfile": True}
    if ext in T1_EXT or name in T1_NAMES:
        try:
            head, truncated = _read(path, BINARY_SCAN_LIMIT)
        except OSError:
            base["reason"] = "unreadable asset"
            return base
        marks = MAGIC.get(ext)
        if marks and not any(head.startswith(m) for m in marks):
            base["reason"] = "content does not match extension (magic bytes)"
            return base
        if ext == ".map":
            if not head.lstrip().startswith(b"{"):
                base["reason"] = "source map is not JSON"
                return base
        if ext == ".webp" and head[8:12] != b"WEBP":
            base["reason"] = "content does not match extension (magic bytes)"
            return base
        if truncated:
            base["reason"] = "asset larger than the scan limit"
            return base
        if ext not in {".mo", ".map"} and CODE.search(head):
            base["reason"] = "code marker inside a binary asset"
            return base
        return {"tier": "T1", "mode": "metadata", "reason": "passive asset; magic bytes and code-marker scan clean", "facts": {"size": size}}
    if ext in T2_EXT or name in T2_NAMES:
        if size > T2_TEXT_LIMIT:
            base["reason"] = "text asset larger than the scan limit"
            return base
        try:
            data = path.read_bytes()
        except OSError:
            base["reason"] = "unreadable asset"
            return base
        if b"\x00" in data[:4096]:
            base["reason"] = "binary content in a text extension"
            return base
        if ext == ".json":
            try:
                json.loads(data.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                base["reason"] = "JSON does not parse"
                return base
        hit = CODE.search(data)
        if hit:
            base["reason"] = "code marker in a text asset: " + hit.group(0).decode("utf-8", "replace")[:40]
            return base
        hit = SECRET.search(data)
        if hit:
            base["reason"] = "possible secret in a text asset"
            return base
        return {"tier": "T2", "mode": "scanned", "reason": "text asset; code-marker and secret scan clean", "facts": {"lines": data.count(b"\n") + 1}}
    return base


def seeds(rel, info):
    """Return (source_related, purpose, behavior, relationships) text for non-T3 files."""
    tier = info["tier"]
    if info.get("lockfile"):
        facts = info["facts"]
        behavior = f"Lockfile parsed by script ({', '.join(f'{k}={v}' for k, v in facts.items() if k in ('entries', 'missing_integrity'))}); hosts: {', '.join(sorted(facts.get('hosts', {}))) or 'n/a'}. Ecosystem audit result must be recorded by the reviewer."
        return True, f"Dependency lockfile ({Path(rel).name}).", behavior, "Pins build/runtime dependency versions; see the manifest next to it."
    label = "binary asset checked by magic bytes and code markers" if tier == "T1" else "text asset checked for code markers and secrets"
    return False, f"Passive asset ({Path(rel).suffix or Path(rel).name}).", f"Tier {tier} ({info['mode']}): {label}; no code or secrets detected.", "No executable role; reviewed by policy rscc-triage-v1 only."
