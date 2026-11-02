import argparse
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import extras  # noqa: E402


class AsvsMatrixTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.run = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def render(self, features=None, overrides=None, level="2"):
        if features is not None:
            (self.run / "asvs_features.json").write_text(json.dumps(features))
        if overrides is not None:
            (self.run / "asvs_overrides.json").write_text(json.dumps(overrides))
        extras.asvs_matrix(argparse.Namespace(run_dir=str(self.run), level=level))
        rows = {}
        for line in (self.run / "asvs-matrix.md").read_text().splitlines():
            if line.startswith("| V"):
                cells = [c.strip() for c in line.strip("|").split("|")]
                rows[cells[0]] = cells
        return rows

    def test_defaults_never_pass_and_cover_l1_l2(self):
        rows = self.render()
        self.assertEqual(len(rows), 253)
        self.assertNotIn("PASS", {r[3] for r in rows.values()})
        self.assertEqual(rows["V5.1.1"][3], "NEEDS VERIFICATION")  # feature not declared absent
        self.assertEqual(rows["V1.4.1"][3], "NOT APPLICABLE")
        self.assertEqual(rows["V3.4.1"][6], "host")

    def test_feature_absence_and_overrides(self):
        rows = self.render({"file_handling": False, "oauth_oidc": True}, {"V8.2.2": ["FAIL", "RSCC-001", "fix"], "V1.2.4": ["PASS", "prepared SQL only"]})
        self.assertEqual(rows["V5.1.1"][3], "NOT APPLICABLE")
        self.assertEqual(rows["V10.1.1"][3], "NEEDS VERIFICATION")  # feature present -> no N/A
        self.assertEqual(rows["V8.2.2"][3:7], ["FAIL", "RSCC-001", "fix", "reviewer"])
        self.assertEqual(rows["V1.2.4"][3], "PASS")

    def test_invalid_inputs_rejected(self):
        with self.assertRaises(ValueError):
            self.render(overrides={"V99.9": ["PASS", "x"]})
        with self.assertRaises(ValueError):
            self.render(overrides={"V1.2.4": ["PASS", ""]})
        (self.run / "asvs_overrides.json").unlink()
        with self.assertRaises(ValueError):
            self.render(features={"not_a_feature": False})

    def test_level_three_rows_excluded_from_overrides_at_level_two(self):
        with self.assertRaises(ValueError):
            self.render(overrides={"V2.3.5": ["PASS", "x"]})


class StandardsCheckTest(unittest.TestCase):
    def test_check_family_states(self):
        fam = {"check": {"type": "regex_max", "url": "u", "pattern": r"v(\d\.\d(?:\.\d)?)", "expect": "4.0.1"}}
        self.assertEqual(extras.check_family(fam, fetch=lambda u, t: (200, "v3.2.1 v4.0.1"))[0], "current")
        self.assertEqual(extras.check_family(fam, fetch=lambda u, t: (200, "v4.0.1 v4.1"))[0], "changed")
        def boom(u, t):
            raise OSError("offline")
        self.assertEqual(extras.check_family(fam, fetch=boom)[0], "unverified")
        gh = {"check": {"type": "github_release", "repo": "x/y", "expect_tag": "v5.0.0_release"}}
        body = json.dumps([{"tag_name": "latest", "published_at": "2026", "prerelease": False, "name": "Bleeding Edge"}, {"tag_name": "v5.0.0_release", "published_at": "2025", "prerelease": False, "name": "5.0.0"}])
        self.assertEqual(extras.check_family(gh, fetch=lambda u, t: (200, body))[0], "current")


class PatternScanTest(unittest.TestCase):
    def test_scan_only_t3_and_prioritises(self):
        with tempfile.TemporaryDirectory() as tmp:
            target, module = Path(tmp) / "t", Path(tmp) / "m"
            target.mkdir(); module.mkdir()
            (target / "a.php").write_text("<?php\necho $_GET['x'];\neval($y);\n")
            (target / "b.php").write_text("<?php\nreturn 1;\n")
            (target / "c.css").write_text("a{} /* $_GET echo */")
            inv = {"target": str(target), "entries": [{"path": p, "kind": "file", "error": ""} for p in ("a.php", "b.php", "c.css")]}
            extras.scan_patterns(argparse.Namespace(top=5), inv, {"c.css": {"tier": "T2"}}, module)
            report = json.loads((module / "pattern_scan.json").read_text())
            self.assertEqual(report["priority_order"][0], "a.php")
            self.assertFalse(any(h.startswith("c.css") for v in report["hits"].values() for h in v))
            self.assertTrue(any("a.php:3" in h for h in report["hits"]["dangerous_calls"]))


if __name__ == "__main__":
    unittest.main()


class CacheAgeTest(unittest.TestCase):
    def setUp(self):
        import shutil
        self.tmp = tempfile.TemporaryDirectory()
        self.refs = Path(self.tmp.name)
        for name in ("standards-cache.json", "asvs-5.0.0.csv"):
            shutil.copy(extras.REFS / name, self.refs / name)
        self.orig = extras.REFS
        extras.REFS = self.refs
        cache = json.loads((self.refs / "standards-cache.json").read_text())
        cache["verified_on"] = "2026-01-01"
        (self.refs / "standards-cache.json").write_text(json.dumps(cache))
        self.cache = cache

    def tearDown(self):
        extras.REFS = self.orig
        self.tmp.cleanup()

    def fake_fetch(self, broken_cwe=None):
        cache = self.cache
        def fetch(url, timeout):
            if "cwe.mitre.org/data/definitions/" in url:
                cid = url.rsplit("/", 1)[1].split(".")[0]
                title = "Changed" if cid == broken_cwe else cache["families"]["cwe"]["titles"][cid]
                return 200, f"<title>CWE - CWE-{cid}: {title} (5.0)</title>"
            if "api.github.com" in url:
                return 200, json.dumps([{"tag_name": "v5.0.0_release", "published_at": "2025", "prerelease": False, "name": "5.0.0"}])
            fam = next((f for f in cache["families"].values() if f.get("check", {}).get("url") == url), None)
            if fam and fam["check"]["type"] == "regex_max":
                return 200, fam["check"]["pattern"].replace("(20\\d\\d)", fam["check"]["expect"]).replace("(\\d+\\.\\d+)", fam["check"]["expect"]).replace("(\\d\\.\\d(?:\\.\\d)?)", fam["check"]["expect"]).replace("(\\d\\.\\d)", fam["check"]["expect"]).replace("\\", "")
            if fam and fam["check"]["type"] == "regex_contains":
                return 200, fam["check"]["pattern"].replace("\\", "")
            return 200, "ok"
        return fetch

    def run_check(self, refresh, broken_cwe=None):
        import datetime as dt
        csv_bytes = (self.refs / "asvs-5.0.0.csv").read_bytes()
        args = argparse.Namespace(offline=False, timeout=1, run_dir=None, write_standards=False, refresh=refresh, max_age_days=None)
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            extras.standards_check(args, fetch=self.fake_fetch(broken_cwe), fetch_bytes=lambda u, t: csv_bytes, today=dt.date(2026, 11, 2))
        return json.loads(buf.getvalue())

    def test_stale_cache_requires_refresh(self):
        report = self.run_check(refresh=False)
        self.assertTrue(report["stale"])
        self.assertIn("--refresh", report["action"])

    def test_refresh_updates_verified_on_when_everything_matches(self):
        report = self.run_check(refresh=True)
        self.assertTrue(report["deep_refresh"]["updated_cache"], report)
        self.assertFalse(report["stale"])
        self.assertEqual(json.loads((self.refs / "standards-cache.json").read_text())["verified_on"], "2026-11-02")

    def test_refresh_keeps_date_when_a_fact_changed(self):
        report = self.run_check(refresh=True, broken_cwe="79")
        self.assertFalse(report["deep_refresh"]["updated_cache"])
        self.assertTrue(any("CWE-79" in p for p in report["deep_refresh"]["problems"]))
        self.assertEqual(json.loads((self.refs / "standards-cache.json").read_text())["verified_on"], "2026-01-01")
        self.assertTrue(report["stale"])
