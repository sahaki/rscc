import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import triage  # noqa: E402


class TriageTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def tier(self, name, data):
        path = self.dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return triage.classify(path, name, len(data))["tier"]

    def test_php_and_js_always_full(self):
        self.assertEqual(self.tier("a.php", b"<?php echo 1;"), "T3")
        self.assertEqual(self.tier("templates/t.php", b"<p>static</p>"), "T3")
        self.assertEqual(self.tier("a.js", b"var a=1;"), "T3")
        self.assertEqual(self.tier("package.json", b"{}"), "T3")
        self.assertEqual(self.tier("x.unknown", b"data"), "T3")

    def test_passive_assets(self):
        self.assertEqual(self.tier("a.png", b"\x89PNG\r\n\x1a\n"), "T1")
        self.assertEqual(self.tier("a.css", b"a{color:red}"), "T2")
        self.assertEqual(self.tier("a.po", b'msgid "a"\nmsgstr "<p>b</p>"\n'), "T2")

    def test_guards_promote(self):
        self.assertEqual(self.tier("fake.png", b"<?php system(1);"), "T3")
        self.assertEqual(self.tier("evil.gif", b"GIF89a<?php system($_GET[1]);"), "T3")
        self.assertEqual(self.tier("a.svg", b'<svg onload="x()"/>'), "T3")
        self.assertEqual(self.tier("a.css", b"a{background:url(javascript:alert(1))}"), "T3")
        self.assertEqual(self.tier("n.md", b'api_key = "abcdefghijklmnopqrstuv"'), "T3")
        self.assertEqual(self.tier("bad.json", b"{not json"), "T3")

    def test_lockfiles(self):
        good = {"lockfileVersion": 3, "packages": {"": {}, "node_modules/a": {"resolved": "https://registry.npmjs.org/a/-/a-1.tgz", "integrity": "sha512-x"}}}
        self.assertEqual(self.tier("package-lock.json", json.dumps(good).encode()), "T2")
        bad = {"lockfileVersion": 3, "packages": {"node_modules/a": {"resolved": "git+ssh://git@evil.example/a.git"}}}
        self.assertEqual(self.tier("sub/package-lock.json", json.dumps(bad).encode()), "T3")
        nointegrity = {"lockfileVersion": 3, "packages": {"node_modules/a": {"resolved": "https://registry.npmjs.org/a/-/a-1.tgz"}}}
        self.assertEqual(self.tier("x/package-lock.json", json.dumps(nointegrity).encode()), "T3")


if __name__ == "__main__":
    unittest.main()
