"""Offline tests for the dependency-manifest parsers."""

import tempfile
import unittest
from pathlib import Path

from malko.scanners import deps


class TestParseRequirements(unittest.TestCase):
    def _write(self, text):
        tmp = tempfile.NamedTemporaryFile(
            "w", suffix="requirements.txt", delete=False, encoding="utf-8"
        )
        tmp.write(text)
        tmp.close()
        self.addCleanup(Path(tmp.name).unlink)
        return tmp.name

    def test_pinned_packages(self):
        path = self._write(
            "requests==2.19.0\n"
            "flask[async]==2.0.1\n"
            "urllib3 == 1.24.1  # inline comment\n"
            "\n"
            "# a full-line comment\n"
        )
        packages, warnings = deps.parse_requirements(path)
        self.assertEqual(
            packages,
            [("requests", "2.19.0"), ("flask", "2.0.1"), ("urllib3", "1.24.1")],
        )
        self.assertEqual(warnings, [])

    def test_unpinned_warns_and_skips(self):
        path = self._write("requests>=2.0\n-r other.txt\ndjango\n")
        packages, warnings = deps.parse_requirements(path)
        self.assertEqual(packages, [])
        self.assertEqual(len(warnings), 3)
        self.assertTrue(any("include files" in w for w in warnings))


class TestParsePackageJson(unittest.TestCase):
    def _write(self, text):
        tmp = tempfile.NamedTemporaryFile(
            "w", suffix="package.json", delete=False, encoding="utf-8"
        )
        tmp.write(text)
        tmp.close()
        self.addCleanup(Path(tmp.name).unlink)
        return tmp.name

    def test_ranges_resolved(self):
        path = self._write(
            '{"dependencies": {"lodash": "^4.17.20", "react": "~17.0.2"},'
            ' "devDependencies": {"jest": ">=26.0.0", "eslint": "8.1.0"}}'
        )
        packages, warnings = deps.parse_package_json(path)
        self.assertEqual(
            packages,
            [
                ("lodash", "4.17.20"),
                ("react", "17.0.2"),
                ("eslint", "8.1.0"),
                ("jest", "26.0.0"),
            ],
        )
        self.assertEqual(warnings, [])

    def test_unresolvable_warns_and_skips(self):
        path = self._write(
            '{"dependencies": {"a": "latest", "b": "*",'
            ' "c": "^1.0.0 || ^2.0.0", "d": "git+https://x/y.git"}}'
        )
        packages, warnings = deps.parse_package_json(path)
        self.assertEqual(packages, [])
        self.assertEqual(len(warnings), 4)

    def test_invalid_json(self):
        path = self._write("{not json")
        packages, warnings = deps.parse_package_json(path)
        self.assertEqual(packages, [])
        self.assertEqual(len(warnings), 1)

    def test_resolve_npm_range(self):
        self.assertEqual(deps._resolve_npm_range("^1.2.3"), "1.2.3")
        self.assertEqual(deps._resolve_npm_range("~2.0"), "2.0")
        self.assertEqual(deps._resolve_npm_range(">=3.1.4 <4"), "3.1.4")
        self.assertIsNone(deps._resolve_npm_range("*"))
        self.assertIsNone(deps._resolve_npm_range("latest"))
        self.assertIsNone(deps._resolve_npm_range("1.x || >=2.5.0"))
        self.assertIsNone(deps._resolve_npm_range("https://example.com/pkg.tgz"))


class TestFindManifests(unittest.TestCase):
    def test_finds_manifests_skips_node_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("requests==2.19.0\n", encoding="utf-8")
            nm = root / "node_modules"
            nm.mkdir()
            (nm / "package.json").write_text("{}", encoding="utf-8")
            sub = root / "sub"
            sub.mkdir()
            (sub / "package.json").write_text("{}", encoding="utf-8")
            found = deps.find_manifests(root)
            self.assertEqual(len(found["requirements.txt"]), 1)
            self.assertEqual([p.name for p in found["package.json"]], ["package.json"])
            self.assertNotIn("node_modules", str(found["package.json"][0]))


if __name__ == "__main__":
    unittest.main()
