import re
import unittest
from pathlib import Path

DASH = Path(__file__).resolve().parents[1] / "dashboard"


class DashboardStaticChecks(unittest.TestCase):
    """The control plane serves a strict CSP (no inline script/style); these guard that contract.
    The UI has NOT been exercised in a browser in the authoring sandbox."""

    def test_files_exist(self):
        for f in ("index.html", "app.js", "style.css"):
            self.assertTrue((DASH / f).is_file(), f)

    def test_no_inline_script_or_style_or_event_handlers(self):
        html = (DASH / "index.html").read_text()
        self.assertNotRegex(html, r"<script(?![^>]*\bsrc=)[^>]*>")
        self.assertNotIn("<style", html)
        self.assertNotRegex(html, r"\son\w+\s*=")
        self.assertNotIn("style=", html)

    def test_js_never_uses_html_injection_sinks(self):
        js = (DASH / "app.js").read_text()
        for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
            self.assertNotIn(sink, js, sink)

    def test_no_external_resources(self):
        for f in ("index.html", "app.js", "style.css"):
            self.assertNotRegex((DASH / f).read_text(), r"https?://", f)

    def test_token_not_persisted_to_browser_storage(self):
        js = (DASH / "app.js").read_text()
        self.assertNotRegex(js, r"localStorage|sessionStorage|document\.cookie")


if __name__ == "__main__":
    unittest.main()
