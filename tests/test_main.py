import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import main

VALID = {
    "user": "ali", "role": "employee", "resource": "wiki", "sensitivity": "low",
    "device_managed": True, "device_patched": True, "country": "LY",
    "mfa_verified": True,
}


def run_cli(*args):
    """Run main.main() with the given arguments; return (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with patch("sys.argv", ["main.py", *args]):
        with redirect_stdout(out), redirect_stderr(err):
            code = main.main()
    return code, out.getvalue(), err.getvalue()


class FileModeTests(unittest.TestCase):
    def run_file(self, content):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "requests.json"
            path.write_text(content, encoding="utf-8")
            return run_cli("--file", str(path))

    def test_valid_file_with_one_bad_entry(self):
        code, out, _ = self.run_file(json.dumps([VALID, {"user": "bad-entry"}]))
        self.assertEqual(code, 0)
        self.assertRegex(out, r"Allowed:\s+1")
        self.assertRegex(out, r"Denied:\s+1")

    def test_missing_file(self):
        code, _, err = run_cli("--file", "missing_file.json")
        self.assertEqual(code, 1)
        self.assertIn("File not found", err)

    def test_invalid_json(self):
        code, _, err = self.run_file("{invalid json")
        self.assertEqual(code, 1)
        self.assertIn("Invalid JSON", err)

    def test_root_must_be_a_list(self):
        code, _, err = self.run_file(json.dumps(VALID))
        self.assertEqual(code, 1)
        self.assertIn("must be a list", err)

    def test_empty_list_is_rejected(self):
        code, _, err = self.run_file("[]")
        self.assertEqual(code, 1)
        self.assertIn("no access requests", err)

    def test_non_object_entry_is_denied_not_crashed(self):
        code, out, _ = self.run_file(json.dumps([42, "text", None]))
        self.assertEqual(code, 0)
        self.assertRegex(out, r"Denied:\s+3")


class DemoModeTests(unittest.TestCase):
    def test_demo_counts_and_alert(self):
        code, out, _ = run_cli("--demo")
        self.assertEqual(code, 0)
        self.assertRegex(out, r"Allowed:\s+1")
        self.assertRegex(out, r"Step-up:\s+1")
        self.assertRegex(out, r"Denied:\s+7")
        self.assertIn("sam was denied 3 consecutive times on payroll-db", out)

    def test_json_flag_prints_valid_audit_log(self):
        code, out, _ = run_cli("--json")
        self.assertEqual(code, 0)
        log_text = out.split("AUDIT LOG JSON\n", 1)[1]
        self.assertEqual(len(json.loads(log_text)), 9)


if __name__ == "__main__":
    unittest.main()
