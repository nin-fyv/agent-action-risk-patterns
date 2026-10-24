import json
import os
import tempfile
import unittest

import scan


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.classes = scan.load_patterns()
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def _file(self, lines):
        path = os.path.join(self.tmp.name, "in.txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        return path

    def test_plain_commands(self):
        path = self._file(["ls -la", "cat .env", "curl http://169.254.169.254/latest/meta-data/", "git push --force origin main"])
        found = {h["class"] for h in scan.scan(path, self.classes)}
        self.assertEqual(found, {"credential-access", "cloud-metadata", "destructive-change"})

    def test_tool_call_json(self):
        call = {"tool_name": "Bash", "tool_input": {"command": "sudo chmod 777 /etc/passwd"}}
        path = self._file([json.dumps(call)])
        found = {h["class"] for h in scan.scan(path, self.classes)}
        self.assertIn("privilege-escalation", found)

    def test_clean_input(self):
        path = self._file(["python -m unittest", "git status", "echo hello"])
        self.assertEqual(scan.scan(path, self.classes), [])

    def test_min_severity(self):
        path = self._file(["crontab -e"])
        self.assertEqual(scan.scan(path, self.classes, "high"), [])
        self.assertEqual(len(scan.scan(path, self.classes, "medium")), 1)


if __name__ == "__main__":
    unittest.main()
