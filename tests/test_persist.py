"""Offline tests for the persistence scanner's pure parsers."""

import os
import unittest

from malko import persist

SCHTASKS_CSV = (
    '"HostName","TaskName","Next Run Time","Status","Logon Mode",'
    '"Last Run Time","Author","Task To Run"\r\n'
    '"PC","\\Updater","N/A","Ready","Interactive","N/A","Me",'
    '"C:\\\\Tools\\\\updater.exe /quiet"\r\n'
    '"PC","\\Empty","N/A","Ready","Interactive","N/A","Me","N/A"\r\n'
)

SCHTASKS_LOCALIZED = (
    '"Имя узла","Имя задачи","Время следующего запуска"\r\n'
    '"PC","\\Updater","N/A"\r\n'
)


class TestResolveTarget(unittest.TestCase):
    def test_quoted_path_with_args(self):
        self.assertEqual(
            persist.resolve_target(r'"C:\Program Files\App\app.exe" /silent'),
            r"C:\Program Files\App\app.exe",
        )

    def test_unquoted_path_with_args(self):
        self.assertEqual(
            persist.resolve_target(r"C:\Tools\run.exe -flag"),
            r"C:\Tools\run.exe",
        )

    def test_env_var_expansion(self):
        os.environ["MALKO_TEST_DIR"] = r"C:\FakeDir"
        try:
            self.assertEqual(
                persist.resolve_target(r"%MALKO_TEST_DIR%\tool.exe --x"),
                r"C:\FakeDir\tool.exe",
            )
        finally:
            del os.environ["MALKO_TEST_DIR"]

    def test_bare_command(self):
        self.assertEqual(persist.resolve_target("notepad.exe"), "notepad.exe")

    def test_empty(self):
        self.assertIsNone(persist.resolve_target(""))
        self.assertIsNone(persist.resolve_target(None))


class TestSchtasksParsing(unittest.TestCase):
    def test_parses_english_csv(self):
        entries, note = persist.parse_schtasks_csv(SCHTASKS_CSV)
        self.assertIsNone(note)
        self.assertEqual(len(entries), 1)  # the "N/A" task is skipped
        self.assertEqual(entries[0]["name"], "\\Updater")
        self.assertEqual(entries[0]["command"], r"C:\\Tools\\updater.exe /quiet")

    def test_localized_csv_skips_with_note(self):
        entries, note = persist.parse_schtasks_csv(SCHTASKS_LOCALIZED)
        self.assertEqual(entries, [])
        self.assertIsNotNone(note)

    def test_garbage_input(self):
        entries, note = persist.parse_schtasks_csv("")
        self.assertEqual(entries, [])


class TestDesktopParsing(unittest.TestCase):
    def test_exec_line(self):
        text = "[Desktop Entry]\nName=App\nExec=/opt/app/run.sh --flag\nType=Application\n"
        self.assertEqual(persist.parse_desktop(text), "/opt/app/run.sh --flag")

    def test_no_exec(self):
        self.assertIsNone(persist.parse_desktop("[Desktop Entry]\nName=App\n"))


if __name__ == "__main__":
    unittest.main()
