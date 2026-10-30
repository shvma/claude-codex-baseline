"""The checker's TOML subset parser: same result as tomllib where both run, a clear error otherwise."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import check  # noqa: E402

try:
    import tomllib
except ModuleNotFoundError:
    tomllib = None

DOCS = [
    (ROOT / "build/codex/requirements.toml").read_text(),
    '[mcp_servers.evil]\ncommand = "sh"\n\n[[hooks.SessionStart]]\nmatcher = "x"\n[[hooks.SessionStart]]\n',
    'mcp_servers = {evil = {command="sh", args = ["-c", \'id\']}}\n',
    '# comment\na.b."c.d" = 1_000  # trailing\n\'lit\' = \'C:\\\\path\'\nf = -1.5e3\nh = 0x1F\nt = true\n'
    'arr = [\n  "x",  # one\n  [1, 2],\n]\ns = "tab\\tq\\"\\u00e9"\nm = """\nline\\\n  joined"""\nml = \'\'\'\nraw\\n\'\'\'\n',
]


class MiniTomlTest(unittest.TestCase):
    def test_build_requirements_parse(self):
        doc = check.MiniToml(DOCS[0]).parse()
        self.assertEqual(doc["allowed_permission_profiles"], {":read-only": True, ":workspace": True})
        self.assertEqual(doc["rules"]["prefix_rules"][0]["pattern"], [{"token": "git"}, {"token": "push"}])
        self.assertIn("github.com", doc["experimental_network"]["domains"])

    @unittest.skipIf(tomllib is None, "tomllib needs Python 3.11+")
    def test_same_as_tomllib(self):
        for text in DOCS:
            self.assertEqual(check.MiniToml(text).parse(), tomllib.loads(text), text)

    def test_unsupported_and_invalid_raise(self):
        for text in ("d = 1979-05-27\n", "a = 1\na = 2\n", "a = \"open\n", "[t\n", "a = [1 2]\n", "x = 1 y = 2\n"):
            with self.assertRaises(check.TOMLError, msg=text):
                check.MiniToml(text).parse()


if __name__ == "__main__":
    unittest.main()
