#!/usr/bin/env python3
"""RSCC snapshot/coverage bookkeeping. This helper does not audit source code."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from uuid import uuid4
sys.dont_write_bytecode = True
from severity import POLICY as SEVERITY_POLICY, assess as assess_severity, reconcile as reconcile_severity
import triage as triage_policy
import extras


STATUSES = {"PASS", "FAIL", "NEEDS VERIFICATION", "NOT APPLICABLE", "UNREVIEWED"}
EXCLUDED_DIRECTORY_NAMES = ("vendor", "node_modules", "build", ".git", ".github", ".gitlab", ".gitea")


def require(ok, message):
    if not ok:
        raise ValueError(message)


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def is_link(path):
    return path.is_symlink() or bool(getattr(path.lstat(), "st_file_attributes", 0) & 0x400)


def safe_output(path):
    """Reject output symlinks/junctions before any write or resolved-path lookup."""
    path = Path(os.path.abspath(path))
    for item in [*reversed(path.parents), path]:
        if item.exists() or item.is_symlink():
            require(not is_link(item), f"Output path contains a link/reparse point: {item}")
    return path


def write(path, value):
    safe_output(path)
    path.write_text(value if isinstance(value, str) else json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def sha_file(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest() if hasattr(hashlib, "file_digest") else _sha_stream(stream)


def _sha_stream(stream):
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def validate_scope(root, target, allow_project_root=False):
    require(root.is_absolute() and target.is_absolute(), "Scope paths must be absolute")
    require(root.resolve(strict=True) == root and target.resolve(strict=True) == target, "Scope path changed or resolves through a different target; select the folder again")
    require(root.is_dir() and target.is_dir(), "Project root and target must be directories")
    require(target.is_relative_to(root), "Target must be inside the project root")
    require(target != root or allow_project_root, "Project root cannot be used as the scan target unless the user explicitly selected it; pass --allow-project-root only for that explicit request")
    require(not target.is_relative_to(root / "rscc"), "Cannot scan the report output tree")
    require(target.name not in EXCLUDED_DIRECTORY_NAMES and not any(part in EXCLUDED_DIRECTORY_NAMES for part in target.relative_to(root).parts), "Target is inside an excluded directory (" + ", ".join(name + "/" for name in EXCLUDED_DIRECTORY_NAMES) + "); select an in-scope folder")


class FolderIgnores:
    """Match only copied, in-target ignore files using an isolated Git worktree."""
    def __init__(self, target, records):
        self.target, self.records, self.temp = target, records, None

    def command(self, *arguments, data=None):
        command = [self.git, "-c", f"core.excludesFile={os.devnull}", "-C", str(self.shadow)]
        if arguments[0] != "init":
            command += [f"--git-dir={self.metadata}", f"--work-tree={self.shadow}", "-c", "core.bare=false"]
        result = subprocess.run([*command, *arguments], input=data, capture_output=True, env=self.environment, timeout=30)
        require(result.returncode in (0, 1), "Git ignore matching failed in the isolated matcher")
        return result.stdout

    def read(self, folder):
        path = folder / ".gitignore"
        if not path.exists() and not path.is_symlink():
            return
        require(not is_link(path) and path.is_file(), f"Cannot safely read .gitignore: {path}")
        content = path.read_bytes()
        if self.temp is None:
            self.git = shutil.which("git")
            require(self.git, "Git CLI is required to apply .gitignore rules; no fallback scan is allowed")
            self.temp = tempfile.TemporaryDirectory(prefix="rscc-ignore-")
            self.shadow = Path(self.temp.name) / "tree"
            self.shadow.mkdir()
            self.metadata = Path(self.temp.name) / "metadata"
            self.environment = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
            self.environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)
            self.command("init", "--bare", "--quiet", "--template=", str(self.metadata))
        relative = path.relative_to(self.target)
        destination = self.shadow / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
        rules = [{"line": number, "pattern": line} for number, line in enumerate(content.decode("utf-8-sig", errors="replace").splitlines(), 1) if line.strip() and not line.startswith("#")]
        self.records.append({"path": relative.as_posix(), "sha256": hashlib.sha256(content).hexdigest(), "rules": rules})

    def matches(self, paths):
        if self.temp is None or not paths:
            return {}
        names = [path.relative_to(self.target).as_posix() + ("/" if path.is_dir() and not is_link(path) else "") for path in paths]
        result = self.command("check-ignore", "--no-index", "--verbose", "-z", "--stdin", data=b"\0".join(os.fsencode(name) for name in names) + b"\0")
        fields = result.split(b"\0")[:-1]
        require(len(fields) % 4 == 0, "Invalid Git ignore matcher output")
        ignored = {}
        for offset in range(0, len(fields), 4):
            source, line, pattern, name = fields[offset:offset + 4]
            if pattern and not pattern.startswith(b"!"):
                ignored[os.fsdecode(name).rstrip("/")] = {"source": os.fsdecode(source), "line": int(line), "pattern": os.fsdecode(pattern)}
        return ignored

    def close(self):
        if self.temp is not None:
            self.temp.cleanup()


def snapshot(root, target, excluded=None, directory_names=EXCLUDED_DIRECTORY_NAMES, allow_project_root=False, use_gitignore=True, gitignore_files=None, gitignore_exclusions=None):
    validate_scope(root, target, allow_project_root)
    entries = []
    output = root / "rscc"
    ignore_records = gitignore_files if gitignore_files is not None else []
    ignores = FolderIgnores(target, ignore_records)

    def walk(folder):
        if use_gitignore:
            ignores.read(folder)
        children = []
        for path in sorted(folder.iterdir(), key=lambda p: p.name):
            if path == output:
                continue
            if path.name in directory_names and path.is_dir():
                if excluded is not None:
                    excluded.append(str(path))
                continue
            children.append(path)
        ignored = ignores.matches(children) if use_gitignore else {}
        for path in children:
            relative = path.relative_to(target).as_posix()
            if relative in ignored:
                if excluded is not None:
                    excluded.append(str(path))
                if gitignore_exclusions is not None:
                    gitignore_exclusions.append({"path": str(path), **ignored[relative]})
                continue
            row = {"path": relative, "kind": "file", "sha256": None, "size": None, "error": ""}
            try:
                if is_link(path):
                    row.update(kind="link", error="Link/reparse point not followed; contents require explicit verification.")
                    row["destination"] = os.readlink(path)
                elif path.is_dir():
                    row["kind"] = "directory"
                    walk(path)
                    continue
                elif stat.S_ISREG(path.stat().st_mode):
                    before = path.stat()
                    row.update(size=before.st_size, sha256=sha_file(path))
                    after = path.stat()
                    require((before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns), f"File changed while hashing: {relative}")
                else:
                    row.update(kind="special", error="Non-regular entry not read.")
            except OSError as exc:
                row["error"] = f"{type(exc).__name__}: unable to inspect entry"
            entries.append(row)

    # A blocked subtree is an explicit directory entry; a blocked root aborts.
    try:
        walk(target)
        for record in ignore_records:
            require(sha_file(target / record["path"]) == record["sha256"], ".gitignore changed during inventory; scan the selected folder again")
    finally:
        ignores.close()
    return sorted(entries, key=lambda row: row["path"])


def index(rows, expected, label):
    require(isinstance(rows, list), f"{label} must be an array")
    paths = [row["path"] for row in rows]
    require(len(paths) == len(set(paths)), f"Duplicate paths in {label}")
    require(set(paths) == set(expected), f"{label} coverage mismatch; missing={sorted(set(expected)-set(paths))}, extra={sorted(set(paths)-set(expected))}")
    result = {row["path"]: row for row in rows}
    for path, row in result.items():
        require(row["sha256"] == expected[path]["sha256"], f"Hash mismatch in {label}: {path}")
    return result


def base(module):
    module = safe_output(module)
    inv = load(module / "inventory.json")
    root, target = Path(inv["root"]), Path(inv["target"])
    validate_scope(root, target, inv.get("project_root_scan_explicit", False))
    require(module == root / "rscc" / inv["module_name"], "Module path does not match recorded scope")
    return module, inv


def notes_for(module, inv):
    expected = {row["path"]: row for row in inv["entries"]}
    notes = index(load(module / "file_notes.json"), expected, "structure notes")
    for row in notes.values():
        require(type(row["source_related"]) is bool and type(row["inspected"]) is bool, f"Classify and inspect {row['path']}")
        for key in ("purpose", "behavior", "relationships"):
            require(isinstance(row.get(key), str) and row[key].strip(), f"Missing {key}: {row['path']}")
    return notes


def current(inv):
    if inv.get("mode") == "files":
        return selected_snapshot(Path(inv["root"]), inv["selected_files"]) == inv["entries"]
    # Preserve the recorded scope of historical runs created before exclusions.
    ignore_records = []
    entries = snapshot(Path(inv["root"]), Path(inv["target"]), directory_names=inv.get("excluded_directory_names", ()), allow_project_root=inv.get("project_root_scan_explicit", False), use_gitignore=inv.get("gitignore_enabled", False), gitignore_files=ignore_records)
    return entries == inv["entries"] and (not inv.get("gitignore_enabled") or ignore_records == inv.get("gitignore_files", []))


def md(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("|", "&#124;").replace("`", "&#96;").replace("\r", "").replace("\n", "<br>")


def table(headers, rows):
    return "\n".join(["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |", *["| " + " | ".join(md(cell) for cell in row) + " |" for row in rows]]) + "\n"


def exclusions_document(inv):
    rules = ", ".join(name + "/" for name in inv.get("excluded_directory_names", ())) or "None (historical scope)"
    matches = {row["path"]: row for row in inv.get("gitignore_exclusions", [])}
    rows = []
    for i, path in enumerate(inv["excluded"]):
        match = matches.get(path)
        reason = f"{match['source']}:{match['line']} ({match['pattern']})" if match else "Review output tree" if i == 0 else "Excluded directory name"
        rows.append([path, reason])
    document = (f"Directory-name exclusions at every depth: {md(rules)}\n\n"
                "Excluded source contents were not enumerated, hashed, read, or reviewed. Ignore-rule metadata is read to determine scope even if the ignore file itself is excluded. Excluded source files are outside coverage counts and are not PASS results.\n\n"
                + table(["Excluded path", "Reason"], rows))
    if inv.get("gitignore_enabled"):
        document += "\n### Local .gitignore rules\n\nRules are refreshed within the selected target only; parent/global ignore sources are not consulted. Fixed exclusions take precedence over reinclusion rules.\n\n"
        document += table(["Ignore file", "Line", "Pattern", "Effect"], [[source["path"], rule["line"], rule["pattern"], "Reinclude if parent is traversable" if rule["pattern"].startswith("!") else "Exclude matching path"] for source in inv.get("gitignore_files", []) for rule in source["rules"]])
        if not inv.get("gitignore_files"):
            document += "\nNo .gitignore files found in the traversed scope.\n"
    return document


def triage_entries(target, entries, enabled=True):
    """Map relative path -> triage record. T3 (full read) for anything not safely classified."""
    result = {}
    for r in entries:
        info = {"tier": "T3", "mode": "full", "reason": "triage disabled" if not enabled else "unreadable or non-regular entry", "facts": {}}
        if enabled and r["kind"] == "file" and not r["error"]:
            try:
                info = triage_policy.classify(Path(target) / r["path"], r["path"], r["size"] or 0)
            except OSError:
                info = {"tier": "T3", "mode": "full", "reason": "unreadable during triage", "facts": {}}
        info["sha256"] = r["sha256"]
        result[r["path"]] = info
    return result


def inventory(args):
    root = Path(args.root).resolve(strict=True)
    target = Path(args.target).resolve(strict=True)
    validate_scope(root, target, args.allow_project_root)
    module_name = args.output_name or target.name
    require(module_name not in {"", ".", ".."} and not re.search(r'[<>:"/\\|?*]', module_name), "Output name must be one folder name")
    module = safe_output(root / "rscc" / module_name)
    if (module / "inventory.json").exists():
        require(load(module / "inventory.json")["target"] == str(target), "Basename collision; ask the user for a distinct output scope")
    excluded = [str(root / "rscc")]
    ignore_records, ignore_matches = [], []
    entries = snapshot(root, target, excluded=excluded, allow_project_root=args.allow_project_root, gitignore_files=ignore_records, gitignore_exclusions=ignore_matches)
    module.mkdir(parents=True, exist_ok=True)
    inv = {"scan_id": str(uuid4()), "root": str(root), "target": str(target), "scope_policy": "selected-target-only", "project_root_scan_explicit": args.allow_project_root, "module_name": module_name, "inventoried_at": datetime.now(timezone.utc).isoformat(), "excluded_directory_names": list(EXCLUDED_DIRECTORY_NAMES), "gitignore_enabled": True, "gitignore_files": ignore_records, "gitignore_exclusions": ignore_matches, "excluded": excluded, "entries": entries}
    triage_rows = triage_entries(target, entries, enabled=not args.no_triage)
    inv["triage_policy"] = triage_policy.POLICY if not args.no_triage else "disabled"
    write(module / "inventory.json", inv)
    write(module / "triage.json", triage_rows)
    notes = []
    for r in entries:
        t = triage_rows[r["path"]]
        row = {"path": r["path"], "sha256": r["sha256"], "source_related": None, "inspected": False, "purpose": "", "behavior": "", "relationships": ""}
        if t["tier"] != "T3":
            source, purpose, behavior, rel = triage_policy.seeds(r["path"], t)
            row.update(source_related=source, inspected=True, purpose=purpose, behavior=behavior, relationships=rel)
        notes.append(row)
    write(module / "file_notes.json", notes)
    tiers = {}
    for t in triage_rows.values():
        tiers[t["tier"]] = tiers.get(t["tier"], 0) + 1
    print(json.dumps({"project_root_output_anchor": str(root), "scan_target": str(target), "structure_file": str(module / "structure_file.md"), "module_dir": str(module), "scan_id": inv["scan_id"], "files": len(entries), "tiers": tiers, "triage": inv["triage_policy"]}))


def structure(args):
    module, inv = base(args.module_dir)
    notes = notes_for(module, inv)
    require(current(inv), "Source drift detected; inventory and document again before starting a run")
    document = f"# Current file structure\n\nTarget: {md(inv['target'])}\n\nScan ID: {inv['scan_id']}\n\nInventoried (UTC): {inv['inventoried_at']}\n\n"
    document += f"Scope rule: Scan only the selected target above. Every listed file path is relative to that target.\n\nProject root (output anchor only): {md(inv['root'])}\n\n"
    document += "Every in-scope entry is accounted for below. Blocked entries are not claims of inspected contents.\n\n"
    document += "## Exclusions\n\n" + exclusions_document(inv) + "\n## In-scope files\n\n"
    document += table(["File", "Kind", "SHA-256", "Source related", "Inspected", "Purpose"], [[r["path"], r["kind"], r["sha256"] or "Unavailable", notes[r["path"]]["source_related"], notes[r["path"]]["inspected"], notes[r["path"]]["purpose"]] for r in inv["entries"]])
    for number, row in enumerate(inv["entries"], 1):
        note = notes[row["path"]]
        document += f"\n## {number}. {md(row['path'])}\n\nPurpose: {md(note['purpose'])}\n\nBehavior: {md(note['behavior'])}\n\nRelationships and boundaries: {md(note['relationships'])}\n\n"
        if row["error"]:
            document += f"Inspection limitation: {md(row['error'])}\n\n"
    write(module / "structure_file.md", document)
    inv["structure_sha256"] = sha_file(module / "structure_file.md")
    inv["notes_sha256"] = sha_file(module / "file_notes.json")
    write(module / "inventory.json", inv)
    print(str(module / "structure_file.md"))


def run_time(utc_offset):
    require(re.fullmatch(r"[+-]\d{2}:\d{2}", utc_offset), "Use a UTC offset such as +07:00")
    hours, minutes = map(int, utc_offset[1:].split(":"))
    require(hours <= 14 and minutes < 60 and (hours < 14 or minutes == 0), "Invalid timezone offset")
    offset = timedelta(hours=hours, minutes=minutes) * (1 if utc_offset[0] == "+" else -1)
    return datetime.now(timezone(offset))


def new_run(module, now):
    run = safe_output(module / now.strftime("%Y%m%d_%H%M"))
    require(not run.exists(), "A run already exists in this minute; wait for the next real minute and retry")
    run.mkdir(parents=True)
    return run


def seed_review(run, inv, triage_rows=None):
    triage_rows = triage_rows or {}
    files = []
    for r in inv["entries"]:
        row = {"path": r["path"], "sha256": r["sha256"], "read_complete": False, "status": "UNREVIEWED", "checks": [], "finding_ids": [], "notes": "", "inspection_mode": "full"}
        t = triage_rows.get(r["path"])
        if t and t["tier"] != "T3" and t.get("sha256") == r["sha256"]:
            row.update(read_complete=True, inspection_mode=t["mode"], notes=f"Tier {t['tier']} ({t['mode']}) by policy {triage_policy.POLICY}: {t['reason']}.")
            if t.get("lockfile"):
                row.update(status="NEEDS VERIFICATION", checks=[{"standard": "OWASP ASVS 5.0.0", "reference": "V15.1.1 / V15.2.1 (dependency advisories)", "status": "NEEDS VERIFICATION", "evidence": "Lockfile structure parsed by script; run the ecosystem audit and replace this check with its result."}])
            else:
                row.update(status="NOT APPLICABLE")
        files.append(row)
    write(run / "review.json", {"scan_id": inv["scan_id"], "severity_policy": SEVERITY_POLICY, "files": files, "findings": []})


def validate_selected_path(root, path):
    require(root.is_absolute() and root.is_dir() and root.resolve(strict=True) == root, "Invalid project root")
    require(path.is_absolute() and path.is_relative_to(root), "Selected file must be inside the project root")
    require(path.resolve(strict=False) == path, "Selected file resolves through a link or changed path; choose its real path explicitly")
    require(not path.is_relative_to(root / "rscc"), "Cannot review generated report files")
    require(not any(part in EXCLUDED_DIRECTORY_NAMES for part in path.relative_to(root).parts[:-1]), "Selected file is inside an excluded directory")


def selected_snapshot(root, selected_files):
    entries = []
    for filename in selected_files:
        path = Path(filename)
        validate_selected_path(root, path)
        row = {"path": path.relative_to(root).as_posix(), "kind": "file", "sha256": None, "size": None, "error": ""}
        try:
            require(path.is_file(), f"Selected file is missing or not a regular file: {path}")
            before = path.stat()
            row.update(size=before.st_size, sha256=sha_file(path))
            after = path.stat()
            require((before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns), f"File changed while hashing: {path}")
        except OSError as exc:
            row["error"] = f"{type(exc).__name__}: unable to read selected file"
        entries.append(row)
    return sorted(entries, key=lambda row: row["path"])


def files_mode(args):
    root = Path(args.root).resolve(strict=True)
    selected = []
    for filename in args.file:
        path = Path(os.path.abspath(root / filename))
        validate_selected_path(root, path)
        require(path.is_file(), f"Selected file is missing or not a regular file: {path}")
        if str(path) not in selected:
            selected.append(str(path))
    entries = selected_snapshot(root, selected)
    now = run_time(args.utc_offset)
    module = safe_output(root / "rscc" / "file-reviews")
    run = new_run(module, now)
    inv = {"scan_id": str(uuid4()), "root": str(root), "mode": "files", "scope_policy": "selected-files-only", "selected_files": selected, "module_name": "file-reviews", "inventoried_at": datetime.now(timezone.utc).isoformat(), "run_at": now.isoformat(), "utc_offset": args.utc_offset, "excluded_directory_names": list(EXCLUDED_DIRECTORY_NAMES), "excluded": [str(root / "rscc")], "entries": entries}
    write(run / "inventory.json", inv)
    seed_review(run, inv)
    print(str(run))


def start(args):
    module, inv = base(args.module_dir)
    notes_for(module, inv)
    require(inv.get("structure_sha256") == sha_file(module / "structure_file.md"), "Regenerate structure_file.md before starting")
    require(inv.get("notes_sha256") == sha_file(module / "file_notes.json"), "Notes changed; regenerate structure_file.md")
    require(current(inv), "Source drift detected; refresh the inventory and map")
    # One scan ID can start one run; another invocation must inventory afresh.
    require(not any(p.is_dir() and (p / "inventory.json").exists() and load(p / "inventory.json").get("scan_id") == inv["scan_id"] for p in module.iterdir()), "This inventory already has a run; start a fresh inventory for a new invocation")
    now = run_time(args.utc_offset)
    run = new_run(module, now)
    inv.update(run_at=now.isoformat(), utc_offset=args.utc_offset)
    write(run / "inventory.json", inv)
    for filename in ("file_notes.json", "structure_file.md"):
        write(run / filename, (module / filename).read_text(encoding="utf-8"))
    triage_rows = load(module / "triage.json") if (module / "triage.json").exists() else {}
    write(run / "triage.json", triage_rows)
    seed_review(run, inv, triage_rows)
    print(str(run))


def finish(args):
    run = safe_output(args.run_dir)
    inv = load(run / "inventory.json")
    file_mode = inv.get("mode") == "files"
    if file_mode:
        root = Path(inv["root"])
        require(inv["scope_policy"] == "selected-files-only" and inv["module_name"] == "file-reviews", "Invalid file review scope")
        require(inv["selected_files"] and len(inv["selected_files"]) == len(set(inv["selected_files"])), "Empty or duplicate file selection")
        for filename in inv["selected_files"]:
            path = Path(filename)
            require(path.is_absolute() and path.is_relative_to(root), "Selected path outside project root")
        require({Path(p).relative_to(root).as_posix() for p in inv["selected_files"]} == {r["path"] for r in inv["entries"]}, "Inventory differs from explicit file selection")
    else:
        validate_scope(Path(inv["root"]), Path(inv["target"]), inv.get("project_root_scan_explicit", False))
    require(run.parent == Path(inv["root"]) / "rscc" / inv["module_name"], "Run path does not match recorded scope")
    require(re.fullmatch(r"\d{8}_\d{4}", run.name), "Invalid run directory name")
    if not file_mode:
        require(inv["structure_sha256"] == sha_file(run / "structure_file.md"), "Run structure snapshot changed")
        require(inv["notes_sha256"] == sha_file(run / "file_notes.json"), "Run notes snapshot changed")
        notes = notes_for(run, inv)
    review = load(run / "review.json")
    require(review["scan_id"] == inv["scan_id"], "Review belongs to a different scan")
    triage_rows = load(run / "triage.json") if (run / "triage.json").exists() and not file_mode else {}
    expected = {row["path"]: row for row in inv["entries"]}
    files = index(review["files"], expected, "review ledger")
    if file_mode:
        notes = {p: {"source_related": True, "inspected": r["read_complete"]} for p, r in files.items()}
    findings = review["findings"]
    ids = [f["id"] for f in findings]
    require(len(ids) == len(set(ids)), "Duplicate finding IDs")
    finding_map = {f["id"]: f for f in findings}
    for finding in findings:
        assess_severity(finding)
        for key in ("id", "category", "title", "description", "impact", "remediation", "confidence", "verification"):
            require(isinstance(finding.get(key), str) and finding[key].strip(), f"Missing finding field: {key}")
        require(finding["severity"] in {"Critical", "High", "Medium", "Low", "Informational"}, "Invalid severity")
        require(finding["confidence"] in {"High", "Medium", "Low"}, "Invalid confidence")
        require(finding.get("locations") and finding.get("standard_refs") and finding.get("acceptance_criteria"), "Finding needs locations, standards, and acceptance criteria")
        for location in finding["locations"]:
            require(location["path"] in files, "Finding location must be in audited target")
            require(location.get("lines") and location.get("evidence"), "Finding location needs lines and evidence")
            require(finding["id"] in files[location["path"]]["finding_ids"], "Finding missing from affected file ledger")
    for path, row in files.items():
        require(row["status"] in STATUSES and type(row["read_complete"]) is bool, f"Invalid review state: {path}")
        mode = row.get("inspection_mode", "full")
        require(mode in {"full", "scanned", "metadata"}, f"Invalid inspection_mode: {path}")
        if mode != "full":
            t = triage_rows.get(path)
            require(t and t["tier"] != "T3" and t.get("sha256") == expected[path]["sha256"] and t["mode"] == mode, f"Only triage tier T1/T2 files may be recorded as {mode}; read this file in full: {path}")
        require(not row["read_complete"] or (notes[path]["inspected"] and expected[path]["kind"] == "file" and not expected[path]["error"]), f"Cannot claim full reading of blocked entry: {path}")
        require(isinstance(row.get("notes"), str) and row["notes"].strip(), f"Review notes missing: {path}")
        for fid in row["finding_ids"]:
            require(fid in finding_map, f"Unknown finding: {fid}")
            require(path in {loc["path"] for loc in finding_map[fid]["locations"]}, f"Finding not located in linked file: {fid}")
        checks = row["checks"]
        for check in checks:
            require(check["status"] in STATUSES - {"UNREVIEWED"}, "Invalid check status")
            require(all(isinstance(check.get(k), str) and check[k].strip() for k in ("standard", "reference", "evidence")), "Check needs standard, reference, and evidence")
        if notes[path]["source_related"] and row["status"] != "UNREVIEWED":
            require(row["status"] != "NOT APPLICABLE" and checks, f"Source file needs applicable checks: {path}")
        if row["status"] in {"PASS", "FAIL"}:
            require(row["read_complete"], f"Cannot give PASS/FAIL before full reading: {path}")
        if checks and row["status"] != "UNREVIEWED":
            states = {c["status"] for c in checks}
            aggregate = "FAIL" if "FAIL" in states else "NEEDS VERIFICATION" if "NEEDS VERIFICATION" in states else "PASS" if "PASS" in states else "NOT APPLICABLE"
            require(row["status"] == aggregate, f"File/check status mismatch: {path}")
        if row["status"] == "FAIL":
            require(any(c["status"] == "FAIL" for c in checks) and row["finding_ids"], f"FAIL needs failing check and finding: {path}")

    try:
        drift = not current(inv)
    except (OSError, ValueError):
        drift = True
    source = [p for p in files if notes[p]["source_related"]]
    blocked = [p for p, row in files.items() if row["status"] == "UNREVIEWED" or expected[p]["kind"] != "file" or expected[p]["error"] or (p in source and not row["read_complete"])]
    docs_missing = [name for name in ("standards.md", "review-summary.md") if not (run / name).is_file() or not (run / name).read_text(encoding="utf-8").strip() or "TODO: complete before finish" in (run / name).read_text(encoding="utf-8")]
    complete = bool(source) and not drift and not blocked and not docs_missing
    reconcile_severity(findings, inv, safe_output(Path(inv["root"]) / "rscc" / "severity_registry.json"), persist=complete)
    review["severity_policy"] = SEVERITY_POLICY
    write(run / "review.json", review)
    file_doc = "# File-by-file review\n\nPASS applies only to assessed controls in this source snapshot. Excluded directory contents are outside this table and its coverage counts; see coverage.md for the scope boundary.\n\n"
    file_doc += table(["File", "SHA-256", "Source", "Inspection", "Status", "Types / findings", "Evidence / notes"], [[p, r["sha256"] or "Unavailable", notes[p]["source_related"], r.get("inspection_mode", "full") if r["read_complete"] else "not read", r["status"], "; ".join(f"{finding_map[i]['category']}: {i}" for i in r["finding_ids"]) or "None recorded", r["notes"]] for p, r in files.items()])
    for p, row in files.items():
        file_doc += f"\n## {md(p)}\n\n" + table(["Standard", "Reference", "Status", "Evidence"], [[c["standard"], c["reference"], c["status"], c["evidence"]] for c in row["checks"]])
    write(run / "file-review.md", file_doc)
    finding_doc = f"# Findings\n\nRSCC severity policy: **{SEVERITY_POLICY}**. Severity is calculated from recorded impact facts; confidence and CVSS are separate fields.\n\n" + table(["ID", "Stable key", "Type", "Severity", "Confidence", "Title", "Files / lines"], [[f["id"], f["stable_key"][:16], f["category"], f["severity"], f["confidence"], f["title"], "; ".join(loc["path"] + ":" + str(loc["lines"]) for loc in f["locations"])] for f in findings])
    if not findings:
        finding_doc += "\nNo findings recorded. See coverage and verification gaps before interpreting this result.\n"
    for f in findings:
        finding_doc += f"\n## {md(f['id'])}: {md(f['title'])}\n\n"
        for key in ("category", "severity", "confidence", "description", "impact", "remediation", "verification"):
            finding_doc += f"{key.replace('_', ' ').title()}: {md(f[key])}\n\n"
        finding_doc += "Severity assessment: " + md(json.dumps(f["severity_assessment"], ensure_ascii=False, sort_keys=True)) + "\n\n"
        if f.get("severity_change"):
            finding_doc += "Severity change: " + md(json.dumps(f["severity_change"], ensure_ascii=False, sort_keys=True)) + "\n\n"
        finding_doc += table(["File", "Lines", "Evidence"], [[loc["path"], loc["lines"], loc["evidence"]] for loc in f["locations"]])
        finding_doc += "\nStandards: " + md("; ".join(f["standard_refs"])) + "\n\nAcceptance criteria:\n\n" + "\n".join("- " + md(item) for item in f["acceptance_criteria"]) + "\n"
        if f.get("cvss"):
            finding_doc += "\nCVSS: " + md(json.dumps(f["cvss"])) + "\n"
    write(run / "findings.md", finding_doc)
    coverage = f"# Coverage\n\nSource reading coverage: **{'COMPLETE' if complete else 'INCOMPLETE'}**\n\n"
    coverage += table(["Measure", "Value"], [["Mode", "Explicit files" if file_mode else "Folder"], ["Target", "; ".join(inv["selected_files"]) if file_mode else inv["target"]], ["Path base", inv["root"] if file_mode else inv["target"]], ["Scan ID", inv["scan_id"]], ["Run time", inv["run_at"]], ["Inventoried entries", len(files)], ["Source-related files", len(source)], ["Fully read source files", sum(files[p]["read_complete"] and files[p].get("inspection_mode", "full") == "full" for p in source)], ["Entries by inspection mode", ", ".join(f"{m}={sum(r.get('inspection_mode', 'full') == m and r['read_complete'] for r in files.values())}" for m in ("full", "scanned", "metadata"))], ["Triage policy", inv.get("triage_policy", "none (all entries read in full)")], ["Unresolved control files", sum(r["status"] == "NEEDS VERIFICATION" for r in files.values())], ["Source drift", drift], ["Missing narrative documents", ", ".join(docs_missing) or "None"], ["Excluded output tree", inv["excluded"][0]]])
    coverage += "\n## Exclusions\n\n" + exclusions_document(inv)
    coverage += "\n## Remaining or blocked entries\n\n" + ("\n".join("- " + md(p) for p in blocked) if blocked else "None.")
    coverage += "\n\nThis is a bookkeeping check, not proof of secure implementation, standards completeness, runtime verification, or certification. Consult the standards/control matrix and verification gaps in review-summary.md.\n"
    write(run / "coverage.md", coverage)
    print(json.dumps({"run": str(run), "source_coverage": "COMPLETE" if complete else "INCOMPLETE", "drift": drift, "blocked": blocked, "findings": len(findings)}))
    return 0 if complete else 2


def paths(args):
    """Print absolute in-scope paths (one per line) for allow-listed searches; never searches outside the inventory."""
    module, inv = base(args.module_dir)
    triage_rows = load(module / "triage.json") if (module / "triage.json").exists() else {}
    wanted_ext = {e.lower() if e.startswith(".") else "." + e.lower() for e in args.ext}
    for row in inv["entries"]:
        if row["kind"] != "file" or row["error"]:
            continue
        tier = triage_rows.get(row["path"], {}).get("tier", "T3")
        if args.tier and tier != args.tier:
            continue
        if wanted_ext and Path(row["path"]).suffix.lower() not in wanted_ext:
            continue
        print(str(Path(inv["target"]) / row["path"]))
    return 0


def scan_patterns_cmd(args):
    module, inv = base(args.module_dir)
    triage_rows = load(module / "triage.json") if (module / "triage.json").exists() else {}
    return extras.scan_patterns(args, inv, triage_rows, module)


def asvs_matrix_cmd(args):
    run = safe_output(args.run_dir)
    require((run / "inventory.json").exists(), "Run directory has no inventory.json")
    return extras.asvs_matrix(args)


def standards_check_cmd(args):
    if args.run_dir:
        run = safe_output(args.run_dir)
        require((run / "inventory.json").exists(), "Run directory has no inventory.json")
        require(not (args.write_standards and (run / "standards.md").exists() and not args.force), "standards.md exists; pass --force to overwrite")
    return extras.standards_check(args)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    inv = commands.add_parser("inventory")
    inv.add_argument("--root", required=True)
    inv.add_argument("--target", required=True)
    inv.add_argument("--output-name", help="Use only for an explicit user-approved basename-collision alias")
    inv.add_argument("--no-triage", action="store_true", help="Disable inspection tiers: every file must be read in full")
    inv.add_argument("--allow-project-root", action="store_true", help="Use only when the user explicitly selected the whole project root as the target")
    selected = commands.add_parser("files", help="Start a review of explicitly listed files without a directory scan or structure map")
    selected.add_argument("--root", required=True)
    selected.add_argument("--file", action="append", required=True)
    selected.add_argument("--utc-offset", required=True)
    for name in ("structure", "start"):
        sub = commands.add_parser(name)
        sub.add_argument("--module-dir", required=True)
        if name == "start":
            sub.add_argument("--utc-offset", required=True)
    commands.add_parser("finish").add_argument("--run-dir", required=True)
    pth = commands.add_parser("paths", help="List inventoried absolute paths for allow-listed grep/read batches")
    pth.add_argument("--module-dir", required=True)
    pth.add_argument("--tier", choices=["T1", "T2", "T3"])
    pth.add_argument("--ext", action="append", default=[])
    scan = commands.add_parser("scan-patterns", help="Allow-listed regex scan of T3 files to prioritise reading (does not replace reading)")
    scan.add_argument("--module-dir", required=True)
    scan.add_argument("--top", type=int, default=15)
    mat = commands.add_parser("asvs-matrix", help="Render asvs-matrix.md from the cached catalogue, asvs_features.json and asvs_overrides.json in the run")
    mat.add_argument("--run-dir", required=True)
    mat.add_argument("--level", choices=["1", "2", "3"], default="2")
    std = commands.add_parser("standards-check", help="Confirm cached standards versions with a few cheap requests")
    std.add_argument("--run-dir")
    std.add_argument("--write-standards", action="store_true", help="Render a standards.md draft into the run from the cache")
    std.add_argument("--force", action="store_true")
    std.add_argument("--offline", action="store_true")
    std.add_argument("--timeout", type=int, default=20)
    std.add_argument("--refresh", action="store_true", help="Deep re-verification (CWE titles, cheat-sheet URLs, ASVS catalogue hash); updates verified_on only if everything matches")
    std.add_argument("--max-age-days", type=int, help="Override the cache age limit (default from standards-cache.json, 15)")
    args = parser.parse_args()
    try:
        return {"inventory": inventory, "files": files_mode, "structure": structure, "start": start, "finish": finish, "paths": paths, "scan-patterns": scan_patterns_cmd, "asvs-matrix": asvs_matrix_cmd, "standards-check": standards_check_cmd}[args.command](args) or 0
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(f"RSCC blocked: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
