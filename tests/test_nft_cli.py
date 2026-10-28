import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from protocolz_nft.cli import main


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def policy_file(self, data):
        p = Path(self.tmp.name) / "p.json"
        p.write_text(json.dumps(data))
        return str(p)

    def test_validate_and_render(self):
        f = self.policy_file({"management_cidrs": ["203.0.113.0/24"]})
        self.assertEqual(run(["validate", f])[0], 0)
        code, out, _ = run(["render", f])
        self.assertEqual(code, 0)
        self.assertIn("policy drop;", out)

    def test_unsafe_policy_exits_2(self):
        code, _, err = run(["validate", self.policy_file({"management_cidrs": []})])
        self.assertEqual(code, 2)
        self.assertIn("policy error", err)

    def test_missing_file_exits_2(self):
        self.assertEqual(run(["validate", "/nonexistent.json"])[0], 2)

    def test_apply_and_rollback_require_explicit_yes(self):
        f = self.policy_file({"management_cidrs": ["203.0.113.0/24"]})
        code, _, err = run(["--state-dir", self.tmp.name, "apply", f])
        self.assertEqual(code, 2)
        self.assertIn("--yes", err)
        self.assertEqual(run(["--state-dir", self.tmp.name, "rollback"])[0], 2)


if __name__ == "__main__":
    unittest.main()
