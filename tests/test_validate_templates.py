import unittest
from pathlib import Path
import sys

# Ensure tools/ is in python path
sys.path.append(str(Path(__file__).parent.parent / "tools"))

from validate_templates import (
    HTMLStructureChecker,
    ValidationResult,
    check_html_structure,
    is_education_file,
)
# We will import the check function we are going to implement
import validate_templates

class TestTemplateValidator(unittest.TestCase):
    def setUp(self):
        self.result = ValidationResult(path="test_template.html")

    def test_existing_html_structure_checks(self):
        """Ensure existing HTML structure check rules work as before."""
        html = "<html><head><title>Test</title><meta charset='UTF-8'><meta name='viewport' content='width=device-width'></head><body>{{.Tracker}}</body></html>"
        checker = check_html_structure(html, self.result)
        self.assertIsNotNone(checker)
        self.assertEqual(len(self.result.errors), 0)
        
        # Missing DOCTYPE is a warning
        self.assertIn("Missing <!DOCTYPE html>", self.result.warnings)

        # Missing body error
        res2 = ValidationResult(path="test_template.html")
        check_html_structure("<html><head><title>Test</title></head></html>", res2)
        self.assertIn("Missing <body> tag", res2.errors)

    def test_html_lang_rule(self):
        """Test the html-lang rule requiring lang attribute on <html>."""
        # 1. No lang attribute -> warning
        html = "<!DOCTYPE html><html><head><title>Test</title></head><body></body></html>"
        checker = HTMLStructureChecker()
        checker.feed(html)
        res = ValidationResult(path="test_template.html")
        validate_templates.check_email_client_compatibility_and_accessibility(html, checker, res, is_education=False)
        self.assertIn("Missing 'lang' attribute on <html> tag", res.warnings)

        # 2. Lang attribute present -> no warning
        html_with_lang = "<!DOCTYPE html><html lang='en'><head><title>Test</title></head><body></body></html>"
        checker_with_lang = HTMLStructureChecker()
        checker_with_lang.feed(html_with_lang)
        res_with_lang = ValidationResult(path="test_template.html")
        validate_templates.check_email_client_compatibility_and_accessibility(html_with_lang, checker_with_lang, res_with_lang, is_education=False)
        self.assertNotIn("Missing 'lang' attribute on <html> tag", res_with_lang.warnings)

    def test_img_alt_and_size_rules(self):
        """Test img-alt (alt text) and img-size (width/height attributes) rules."""
        # 1. Missing alt, width, and height -> warnings
        html = '<img src="logo.png">'
        checker = HTMLStructureChecker()
        checker.feed(html)
        res = ValidationResult(path="test_template.html")
        validate_templates.check_email_client_compatibility_and_accessibility(html, checker, res, is_education=False)
        self.assertTrue(any("missing 'alt' attribute" in w for w in res.warnings))
        self.assertTrue(any("missing HTML 'width' or 'height'" in w for w in res.warnings))

        # 2. Present alt and width/height -> no warnings
        html_ok = '<img src="logo.png" alt="Logo" width="100" height="50">'
        checker_ok = HTMLStructureChecker()
        checker_ok.feed(html_ok)
        res_ok = ValidationResult(path="test_template.html")
        validate_templates.check_email_client_compatibility_and_accessibility(html_ok, checker_ok, res_ok, is_education=False)
        self.assertFalse(any("missing 'alt' attribute" in w for w in res_ok.warnings))
        self.assertFalse(any("missing HTML 'width' or 'height'" in w for w in res_ok.warnings))

        # 3. Empty alt is allowed for accessibility (decorative images)
        html_empty_alt = '<img src="spacer.png" alt="" width="1" height="1">'
        checker_empty_alt = HTMLStructureChecker()
        checker_empty_alt.feed(html_empty_alt)
        res_empty_alt = ValidationResult(path="test_template.html")
        validate_templates.check_email_client_compatibility_and_accessibility(html_empty_alt, checker_empty_alt, res_empty_alt, is_education=False)
        self.assertFalse(any("missing 'alt' attribute" in w for w in res_empty_alt.warnings))

    def test_link_text_rule(self):
        """Test link-text rule requiring discernible text or label on links."""
        # 1. Empty link -> warning
        html = '<a href="https://example.com"></a>'
        checker = HTMLStructureChecker()
        checker.feed(html)
        res = ValidationResult(path="test_template.html")
        validate_templates.check_email_client_compatibility_and_accessibility(html, checker, res, is_education=False)
        self.assertTrue(any("missing discernible text" in w for w in res.warnings))

        # 2. Link with text -> no warning
        html_text = '<a href="https://example.com">Click Here</a>'
        checker_text = HTMLStructureChecker()
        checker_text.feed(html_text)
        res_text = ValidationResult(path="test_template.html")
        validate_templates.check_email_client_compatibility_and_accessibility(html_text, checker_text, res_text, is_education=False)
        self.assertFalse(any("missing discernible text" in w for w in res_text.warnings))

        # 3. Link with image with alt -> no warning
        html_img_alt = '<a href="https://example.com"><img src="btn.png" alt="Submit"></a>'
        checker_img_alt = HTMLStructureChecker()
        checker_img_alt.feed(html_img_alt)
        res_img_alt = ValidationResult(path="test_template.html")
        validate_templates.check_email_client_compatibility_and_accessibility(html_img_alt, checker_img_alt, res_img_alt, is_education=False)
        self.assertFalse(any("missing discernible text" in w for w in res_img_alt.warnings))

        # 4. Link with aria-label -> no warning
        html_aria = '<a href="https://example.com" aria-label="Social Link"></a>'
        checker_aria = HTMLStructureChecker()
        checker_aria.feed(html_aria)
        res_aria = ValidationResult(path="test_template.html")
        validate_templates.check_email_client_compatibility_and_accessibility(html_aria, checker_aria, res_aria, is_education=False)
        self.assertFalse(any("missing discernible text" in w for w in res_aria.warnings))

    def test_unsupported_layouts(self):
        """Test detection of flex, grid, position, and float in styles."""
        # 1. Inline styles with position and flex
        html = '<div style="position: absolute; display: flex;"></div>'
        checker = HTMLStructureChecker()
        checker.feed(html)
        res = ValidationResult(path="test_template.html")
        validate_templates.check_email_client_compatibility_and_accessibility(html, checker, res, is_education=False)
        self.assertTrue(any("layout pattern 'position' found" in w for w in res.warnings))
        self.assertTrue(any("layout pattern 'flex' found" in w for w in res.warnings))

        # 2. Style blocks with grid and float
        html_css = """
        <style>
            .grid-container { display: grid; }
            .sidebar { float: left; }
        </style>
        """
        checker_css = HTMLStructureChecker()
        checker_css.feed(html_css)
        res_css = ValidationResult(path="test_template.html")
        validate_templates.check_email_client_compatibility_and_accessibility(html_css, checker_css, res_css, is_education=False)
        self.assertTrue(any("layout pattern 'grid' found" in w for w in res_css.warnings))
        self.assertTrue(any("layout pattern 'float' found" in w for w in res_css.warnings))

    def test_css_selectors_compatibility(self):
        """Test unsupported CSS selectors inside <style> blocks."""
        cases = [
            ("div > p { color: red; }", "child combinator"),
            ("h1 + p { color: red; }", "adjacent sibling combinator"),
            ("h1 ~ p { color: red; }", "general sibling combinator"),
            ("[type='text'] { color: red; }", "attribute selector"),
            (".btn::before { content: ''; }", "pseudo-element"),
            ("li:nth-child(2) { color: red; }", "pseudo-class ':nth-child'"),
            ("input:not(:checked) { color: red; }", "pseudo-class ':not'"),
            (".btn:hover { color: red; }", "pseudo-class ':hover'"),
        ]
        for css, expected_reason in cases:
            html = f"<style>{css}</style>"
            checker = HTMLStructureChecker()
            checker.feed(html)
            res = ValidationResult(path="test_template.html")
            validate_templates.check_email_client_compatibility_and_accessibility(html, checker, res, is_education=False)
            self.assertTrue(
                any(expected_reason in w for w in res.warnings),
                f"Expected to find warning containing '{expected_reason}' for CSS: {css}"
            )

    def test_external_stylesheet_links(self):
        """Test warning on external stylesheet links."""
        # 1. External CSS -> warning
        html = '<link rel="stylesheet" href="https://example.com/style.css">'
        checker = HTMLStructureChecker()
        checker.feed(html)
        res = ValidationResult(path="test_template.html")
        validate_templates.check_email_client_compatibility_and_accessibility(html, checker, res, is_education=False)
        self.assertTrue(any("External stylesheet link found" in w for w in res.warnings))

        # 2. Local CSS -> no warning
        html_local = '<link rel="stylesheet" href="local.css">'
        checker_local = HTMLStructureChecker()
        checker_local.feed(html_local)
        res_local = ValidationResult(path="test_template.html")
        validate_templates.check_email_client_compatibility_and_accessibility(html_local, checker_local, res_local, is_education=False)
        self.assertFalse(any("External stylesheet link found" in w for w in res_local.warnings))

    def test_dark_mode_rule(self):
        """Test warning when text/background colors are defined without dark mode handling."""
        # 1. Colors defined but no dark mode handling -> warning
        html = '<style>body { background-color: #ffffff; color: #333333; }</style>'
        checker = HTMLStructureChecker()
        checker.feed(html)
        res = ValidationResult(path="test_template.html")
        validate_templates.check_email_client_compatibility_and_accessibility(html, checker, res, is_education=False)
        self.assertTrue(any("no dark mode handling" in w for w in res.warnings))

        # 2. Colors defined and prefers-color-scheme media query present -> no warning
        html_prefers = """
        <style>
            body { background: white; color: black; }
            @media (prefers-color-scheme: dark) {
                body { background: black; color: white; }
            }
        </style>
        """
        checker_prefers = HTMLStructureChecker()
        checker_prefers.feed(html_prefers)
        res_prefers = ValidationResult(path="test_template.html")
        validate_templates.check_email_client_compatibility_and_accessibility(html_prefers, checker_prefers, res_prefers, is_education=False)
        self.assertFalse(any("no dark mode handling" in w for w in res_prefers.warnings))

        # 3. Colors defined and color-scheme meta tag present -> no warning
        html_meta = """
        <html>
        <head>
            <meta name="color-scheme" content="light dark">
            <style>body { color: #333; }</style>
        </head>
        </html>
        """
        checker_meta = HTMLStructureChecker()
        checker_meta.feed(html_meta)
        res_meta = ValidationResult(path="test_template.html")
        validate_templates.check_email_client_compatibility_and_accessibility(html_meta, checker_meta, res_meta, is_education=False)
        self.assertFalse(any("no dark mode handling" in w for w in res_meta.warnings))

    def test_comment_suppression(self):
        """Test that <!-- validate:allow <rule> --> successfully suppresses warnings."""
        # 1. Without allow comment -> warning
        html = "<!DOCTYPE html><html><head><title>Test</title></head><body></body></html>"
        checker = HTMLStructureChecker()
        checker.feed(html)
        res = ValidationResult(path="test_template.html")
        validate_templates.check_email_client_compatibility_and_accessibility(html, checker, res, is_education=False)
        self.assertTrue(any("Missing 'lang' attribute" in w for w in res.warnings))

        # 2. With allow comment -> no warning for html-lang
        html_allow = "<!-- validate:allow html-lang -->" + html
        checker_allow = HTMLStructureChecker()
        checker_allow.feed(html_allow)
        res_allow = ValidationResult(path="test_template.html")
        validate_templates.check_email_client_compatibility_and_accessibility(html_allow, checker_allow, res_allow, is_education=False)
        self.assertFalse(any("Missing 'lang' attribute" in w for w in res_allow.warnings))

    def test_education_files_ignore_email_compat_rules(self):
        """Ensure compatibility rules are skipped for education files (is_education=True)."""
        html = '<style>.flex { display: flex; } [type="text"] { color: red; }</style>'
        checker = HTMLStructureChecker()
        checker.feed(html)
        res = ValidationResult(path="education/test_edu.html")
        validate_templates.check_email_client_compatibility_and_accessibility(html, checker, res, is_education=True)
        # Sibling combinators/flex layout etc. should not warn on education pages
        self.assertFalse(any("layout pattern" in w for w in res.warnings))
        self.assertFalse(any("Unsupported CSS selector" in w for w in res.warnings))


if __name__ == "__main__":
    unittest.main()
