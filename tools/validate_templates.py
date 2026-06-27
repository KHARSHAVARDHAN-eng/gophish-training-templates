#!/usr/bin/env python3
"""
GoPhish Template Validator
Validates all phishing training templates for required variables, structure, and quality.

Usage:
    python3 validate_templates.py                  # Validate all templates
    python3 validate_templates.py --dir <path>     # Validate a specific directory
    python3 validate_templates.py --file <path>    # Validate a single file
    python3 validate_templates.py --strict         # Fail on warnings too
"""

import os
import re
import sys
import json
import argparse
from pathlib import Path
from html.parser import HTMLParser
from dataclasses import dataclass, field
from typing import List, Optional

ROOT = Path(__file__).parent.parent

# ── Constants ────────────────────────────────────────────────────────────────

REQUIRED_VARS = ["{{.URL}}", "{{.Tracker}}"]
RECOMMENDED_VARS = ["{{.FirstName}}", "{{.Email}}"]
OPTIONAL_VARS = ["{{.LastName}}", "{{.Date}}"]

REQUIRED_META_TAGS = ["charset", "viewport"]

EDUCATION_DIRS = ["education"]

SKIP_DIRS = {".git", "tools", "landing-pages", "campaign-guides"}
SKIP_FILES = {"credential-harvest.html", "education-notification.html"}


# ── Result dataclasses ───────────────────────────────────────────────────────

@dataclass
class ValidationResult:
    path: str
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    info: List[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return len(self.errors) == 0

    @property
    def has_warnings(self) -> bool:
        return len(self.warnings) > 0


# ── HTML structure checker ───────────────────────────────────────────────────

class HTMLStructureChecker(HTMLParser):
    def __init__(self):
        super().__init__()
        self.has_doctype = False
        self.has_html = False
        self.has_head = False
        self.has_body = False
        self.meta_tags = {}
        self.has_title = False
        self._in_title = False
        self.title_text = ""
        self.tag_stack = []

    def handle_decl(self, decl):
        if decl.lower().startswith("doctype"):
            self.has_doctype = True

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        tag_lower = tag.lower()

        if tag_lower == "html":
            self.has_html = True
        elif tag_lower == "head":
            self.has_head = True
        elif tag_lower == "body":
            self.has_body = True
        elif tag_lower == "title":
            self.has_title = True
            self._in_title = True
        elif tag_lower == "meta":
            name = attrs_dict.get("name", "").lower()
            charset = attrs_dict.get("charset", "")
            if charset:
                self.meta_tags["charset"] = charset
            if name == "viewport":
                self.meta_tags["viewport"] = attrs_dict.get("content", "")

        if tag_lower not in ("br", "hr", "img", "input", "meta", "link", "area", "base"):
            self.tag_stack.append(tag_lower)

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self._in_title = False
        if self.tag_stack and self.tag_stack[-1] == tag.lower():
            self.tag_stack.pop()

    def handle_data(self, data):
        if self._in_title:
            self.title_text += data


# ── Individual checks ────────────────────────────────────────────────────────

def check_gophish_variables(content: str, result: ValidationResult, is_education: bool):
    """Verify required and recommended GoPhish template variables."""
    if is_education:
        # Education pages don't need GoPhish variables
        return

    for var in REQUIRED_VARS:
        if var not in content:
            result.errors.append(f"Missing required GoPhish variable: {var}")

    for var in RECOMMENDED_VARS:
        if var not in content:
            result.warnings.append(f"Missing recommended GoPhish variable: {var}")

    # Check for common typos
    typos = {
        "{{.Url}}": "{{.URL}}",
        "{{.url}}": "{{.URL}}",
        "{{.tracker}}": "{{.Tracker}}",
        "{{.firstname}}": "{{.FirstName}}",
        "{{.email}}": "{{.Email}}",
    }
    for typo, correct in typos.items():
        if typo in content:
            result.errors.append(f"Typo in GoPhish variable '{typo}' — should be '{correct}'")

    # Warn about variables in href attributes that aren't using {{.URL}}
    bare_url_pattern = re.compile(r'href="http[^"]*\{\{\.', re.IGNORECASE)
    if bare_url_pattern.search(content):
        result.warnings.append("Possible misuse of {{.URL}} inside an href — ensure it's used as the complete href value")


def check_html_structure(content: str, result: ValidationResult):
    """Check basic HTML structure validity."""
    checker = HTMLStructureChecker()
    try:
        checker.feed(content)
    except Exception as e:
        result.errors.append(f"HTML parse error: {e}")
        return

    if not checker.has_doctype:
        result.warnings.append("Missing <!DOCTYPE html>")

    if not checker.has_html:
        result.errors.append("Missing <html> tag")

    if not checker.has_head:
        result.errors.append("Missing <head> tag")

    if not checker.has_body:
        result.errors.append("Missing <body> tag")

    if not checker.has_title:
        result.warnings.append("Missing <title> tag")
    elif not checker.title_text.strip():
        result.warnings.append("<title> tag is empty")

    for required in REQUIRED_META_TAGS:
        if required not in checker.meta_tags:
            if required == "viewport":
                result.errors.append("Missing <meta name='viewport'> tag — template is not mobile-responsive")
            else:
                result.warnings.append(f"Missing <meta {required}> tag")


def check_external_dependencies(content: str, result: ValidationResult, file_path: Path):
    """Check for problematic external dependencies."""
    # Bootstrap 3.x CDN is outdated
    if "bootstrap/3.3" in content or "bootstrap/3.2" in content or "bootstrap/3.1" in content:
        result.warnings.append(
            "Uses outdated Bootstrap 3.x CDN — consider migrating to inline CSS or Bootstrap 5"
        )

    # External CDN resources can break if offline
    external_cdn_pattern = re.compile(
        r'(src|href)="https?://(cdn\.|maxcdn\.|cdnjs\.|unpkg\.)', re.IGNORECASE
    )
    cdns = external_cdn_pattern.findall(content)
    if cdns:
        result.warnings.append(
            f"Found {len(cdns)} external CDN reference(s) — templates may fail without internet access"
        )

    # External hotlinked images leak target IP to third-party servers and break in airgapped environments
    external_img_pattern = re.compile(r'<img\s[^>]*src="https?://(?!data:)', re.IGNORECASE)
    hotlinked_imgs = external_img_pattern.findall(content)
    if hotlinked_imgs:
        result.errors.append(
            f"Found {len(hotlinked_imgs)} hotlinked external image(s) — use inline SVG, emoji, or base64 data URIs instead; "
            f"external images leak target IP addresses and fail in airgapped deployments"
        )


def check_education_page(template_path: Path, result: ValidationResult):
    """Check that a corresponding education page exists."""
    category_dir = template_path.parent
    education_dir = category_dir / "education"

    if not education_dir.exists():
        result.warnings.append(
            f"No education/ directory found in {category_dir.name} — consider adding educational follow-up content"
        )
        return

    edu_files = list(education_dir.glob("*.html"))
    if not edu_files:
        result.warnings.append(
            f"Education directory exists but contains no HTML files in {category_dir.name}"
        )


def check_metadata(template_path: Path, result: ValidationResult):
    """Check that metadata.json exists, satisfies the schema, and references this template."""
    metadata_path = template_path.parent / "metadata.json"

    if not metadata_path.exists():
        result.errors.append(
            "No metadata.json found in this directory"
        )
        return

    try:
        with open(metadata_path, encoding="utf-8") as f:
            metadata = json.load(f)
    except json.JSONDecodeError as e:
        result.errors.append(f"metadata.json is invalid JSON: {e}")
        return

    # Validate top-level metadata fields
    # category must match the directory name
    category = metadata.get("category")
    expected_category = template_path.parent.name
    if not category:
        result.errors.append("metadata.json missing top-level field 'category'")
    elif category != expected_category:
        result.errors.append(
            f"metadata.json top-level field 'category' ('{category}') does not match directory name ('{expected_category}')"
        )

    # gophish_version_tested must exist
    if not metadata.get("gophish_version_tested"):
        result.errors.append("metadata.json missing top-level field 'gophish_version_tested'")

    # last_updated must exist and be valid YYYY-MM-DD format
    last_updated = metadata.get("last_updated")
    if not last_updated:
        result.errors.append("metadata.json missing top-level field 'last_updated'")
    elif not re.match(r"^\d{4}-\d{2}-\d{2}$", str(last_updated)):
        result.errors.append(
            f"metadata.json top-level field 'last_updated' ('{last_updated}') must be in YYYY-MM-DD ISO format"
        )

    # Check if this template is referenced in metadata
    templates = metadata.get("templates", [])
    if not isinstance(templates, list):
        result.errors.append("metadata.json 'templates' field must be a list")
        return

    template_filenames = [t.get("filename", "") for t in templates if isinstance(t, dict)]

    if template_path.name not in template_filenames:
        result.errors.append(
            f"Template '{template_path.name}' is not listed in metadata.json"
        )
        return

    # Validate metadata fields for this template
    for tmpl in templates:
        if not isinstance(tmpl, dict):
            result.errors.append("metadata.json template entries must be JSON objects")
            continue

        if tmpl.get("filename") == template_path.name:
            # 1. Required fields: filename, name, attack_vector, difficulty, estimated_click_rate,
            #    gophish_variables, suggested_subject_lines, education_page, tags, notes.
            required_fields = [
                "filename", "name", "attack_vector", "difficulty", "estimated_click_rate",
                "gophish_variables", "suggested_subject_lines", "education_page", "tags", "notes"
            ]
            for field_name in required_fields:
                if tmpl.get(field_name) is None or tmpl.get(field_name) == "":
                    result.errors.append(f"metadata.json template entry missing required field '{field_name}'")

            # 2. Difficulty enum validation
            valid_difficulties = {"beginner", "intermediate", "advanced"}
            difficulty = tmpl.get("difficulty")
            if difficulty and difficulty not in valid_difficulties:
                result.errors.append(
                    f"Invalid difficulty '{difficulty}' — must be one of: {sorted(list(valid_difficulties))}"
                )

            # 3. Attack vector enum validation
            valid_attack_vectors = {"credential_harvest", "data_entry", "attachment", "link_only"}
            attack_vector = tmpl.get("attack_vector")
            if attack_vector and attack_vector not in valid_attack_vectors:
                result.errors.append(
                    f"Invalid attack_vector '{attack_vector}' — must be one of: {sorted(list(valid_attack_vectors))}"
                )

            # 4. Format validation for estimated_click_rate
            click_rate = tmpl.get("estimated_click_rate")
            if click_rate and not re.match(r"^\d{1,3}-\d{1,3}%$", str(click_rate)):
                result.errors.append(
                    f"Invalid estimated_click_rate '{click_rate}' — must be a range like '20-40%'"
                )

            # 5. suggested_subject_lines validation (non-empty list)
            subjects = tmpl.get("suggested_subject_lines")
            if subjects is not None:
                if not isinstance(subjects, list):
                    result.errors.append("metadata.json 'suggested_subject_lines' must be an array")
                elif len(subjects) == 0:
                    result.errors.append("metadata.json 'suggested_subject_lines' must contain at least one entry")

            # 6. gophish_variables validation (must include {{.URL}} and {{.Tracker}})
            gophish_vars = tmpl.get("gophish_variables")
            if gophish_vars is not None:
                if not isinstance(gophish_vars, list):
                    result.errors.append("metadata.json 'gophish_variables' must be an array")
                else:
                    if "{{.URL}}" not in gophish_vars:
                        result.errors.append("metadata.json 'gophish_variables' missing required variable '{{.URL}}'")
                    if "{{.Tracker}}" not in gophish_vars:
                        result.errors.append("metadata.json 'gophish_variables' missing required variable '{{.Tracker}}'")


KNOWN_GOPHISH_VARS = {
    "{{.Email}}", "{{.FirstName}}", "{{.LastName}}", "{{.Position}}",
    "{{.Phone}}", "{{.Company}}", "{{.URL}}", "{{.Tracker}}",
    "{{.From}}", "{{.Date}}", "{{.RId}}",
}

VAR_PATTERN = re.compile(r"\{\{\.([A-Za-z]+)")


def check_metadata_variables(content: str, template_path: Path, result: ValidationResult):
    """Warn when declared gophish_variables in metadata don't match what the template actually uses."""
    metadata_path = template_path.parent / "metadata.json"
    if not metadata_path.exists():
        return

    try:
        metadata = json.loads(metadata_path.read_text())
    except json.JSONDecodeError:
        return

    tmpl_entry = next(
        (t for t in metadata.get("templates", []) if t.get("filename") == template_path.name),
        None,
    )
    if tmpl_entry is None:
        return

    declared = set(tmpl_entry.get("gophish_variables", []))
    used = {f"{{{{.{v}}}}}" for v in VAR_PATTERN.findall(content)}

    missing_from_meta = used - declared
    extra_in_meta = declared - used

    for var in sorted(missing_from_meta):
        if var not in KNOWN_GOPHISH_VARS:
            result.warnings.append(
                f"Template uses '{var}' which is not a standard GoPhish variable — "
                f"verify it is supported and add it to gophish_variables in metadata.json"
            )
        else:
            result.warnings.append(
                f"Template uses '{var}' but it is not listed in gophish_variables in metadata.json — "
                f"add it so operators know to include it in their campaign target CSV"
            )

    for var in sorted(extra_in_meta):
        result.warnings.append(
            f"metadata.json declares '{var}' in gophish_variables but it is not used in the template — "
            f"remove it to avoid misleading operators"
        )


def check_tracker_placement(content: str, result: ValidationResult, is_education: bool):
    """Verify {{.Tracker}} is placed correctly (outside of visible content, typically last in body)."""
    if is_education:
        return

    if "{{.Tracker}}" not in content:
        return  # Already caught by check_gophish_variables

    # Tracker should be near the end of the body, not inside visible containers
    tracker_idx = content.rfind("{{.Tracker}}")
    body_close_idx = content.lower().rfind("</body>")

    if body_close_idx != -1 and tracker_idx > body_close_idx:
        result.warnings.append("{{.Tracker}} appears after </body> — move it inside <body>")

    # Check if tracker is wrapped in a display:none or similar — acceptable
    tracker_context = content[max(0, tracker_idx - 100):tracker_idx + 50]
    if "display:none" not in tracker_context and "display: none" not in tracker_context:
        result.info.append("{{.Tracker}} is not wrapped in a hidden element — this is fine but some deployments prefer hiding it")


def check_file_size(file_path: Path, result: ValidationResult):
    """Warn if template is unusually large (may indicate embedded images bloating the file)."""
    size_kb = file_path.stat().st_size / 1024
    if size_kb > 500:
        result.warnings.append(f"Template file is {size_kb:.0f}KB — consider optimizing embedded assets")
    result.info.append(f"File size: {size_kb:.1f}KB")


# ── Main validator ───────────────────────────────────────────────────────────

def is_education_file(file_path: Path) -> bool:
    """Determine if this file is an education page (not a phishing template)."""
    return "education" in [p.name for p in file_path.parents]


def validate_file(file_path: Path) -> ValidationResult:
    result = ValidationResult(path=str(file_path.relative_to(ROOT)))

    try:
        content = file_path.read_text(encoding="utf-8")
    except Exception as e:
        result.errors.append(f"Cannot read file: {e}")
        return result

    is_education = is_education_file(file_path)

    check_html_structure(content, result)
    check_gophish_variables(content, result, is_education)
    check_external_dependencies(content, result, file_path)
    check_tracker_placement(content, result, is_education)
    check_file_size(file_path, result)

    if not is_education:
        check_education_page(file_path, result)
        check_metadata(file_path, result)
        check_metadata_variables(content, file_path, result)

    return result


def find_templates(base_dir: Path) -> List[Path]:
    """Recursively find all HTML template files, skipping excluded directories."""
    templates = []
    for path in sorted(base_dir.rglob("*.html")):
        # Skip excluded directories
        parts = set(path.parts)
        if SKIP_DIRS & parts:
            continue
        if path.name in SKIP_FILES:
            continue
        templates.append(path)
    return templates


# ── Output ───────────────────────────────────────────────────────────────────

RESET = "\033[0m"
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BLUE = "\033[94m"
BOLD = "\033[1m"
DIM = "\033[2m"


def print_result(result: ValidationResult, verbose: bool = False):
    status = f"{GREEN}✓ PASS{RESET}" if result.passed else f"{RED}✗ FAIL{RESET}"
    warn_str = f" {YELLOW}({len(result.warnings)} warnings){RESET}" if result.warnings else ""
    print(f"  {status}{warn_str}  {DIM}{result.path}{RESET}")

    for err in result.errors:
        print(f"    {RED}ERROR{RESET}   {err}")

    for warn in result.warnings:
        print(f"    {YELLOW}WARN{RESET}    {warn}")

    if verbose:
        for info in result.info:
            print(f"    {BLUE}INFO{RESET}    {info}")


def print_summary(results: List[ValidationResult], strict: bool = False):
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    failed = total - passed
    warned = sum(1 for r in results if r.has_warnings)
    total_errors = sum(len(r.errors) for r in results)
    total_warnings = sum(len(r.warnings) for r in results)

    print()
    print(f"{BOLD}{'─' * 60}{RESET}")
    print(f"{BOLD}Summary:{RESET} {total} templates validated")
    print(f"  {GREEN}Passed:{RESET}   {passed}")
    if failed:
        print(f"  {RED}Failed:{RESET}   {failed} ({total_errors} errors)")
    if warned:
        print(f"  {YELLOW}Warnings:{RESET} {warned} templates with {total_warnings} warnings")
    print(f"{BOLD}{'─' * 60}{RESET}")

    if strict:
        overall_pass = failed == 0 and warned == 0
    else:
        overall_pass = failed == 0

    if overall_pass:
        print(f"{GREEN}{BOLD}✓ All checks passed!{RESET}")
    else:
        print(f"{RED}{BOLD}✗ Validation failed.{RESET}")

    return overall_pass


# ── Entry point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Validate GoPhish training templates")
    parser.add_argument("--dir", type=Path, default=ROOT, help="Directory to scan (default: repo root)")
    parser.add_argument("--file", type=Path, help="Validate a single file")
    parser.add_argument("--strict", action="store_true", help="Fail on warnings as well as errors")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show informational messages")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args()

    if args.file:
        files = [args.file.resolve()]
    else:
        files = find_templates(args.dir.resolve())

    if not files:
        print(f"{YELLOW}No HTML template files found.{RESET}")
        sys.exit(0)

    print(f"{BOLD}GoPhish Template Validator{RESET}")
    print(f"Scanning {len(files)} template(s)...\n")

    results = []
    for file_path in files:
        result = validate_file(file_path)
        results.append(result)
        if not args.json:
            print_result(result, verbose=args.verbose)

    if args.json:
        output = [
            {
                "path": r.path,
                "passed": r.passed,
                "errors": r.errors,
                "warnings": r.warnings,
            }
            for r in results
        ]
        print(json.dumps(output, indent=2))
        all_passed = all(r.passed for r in results)
        if args.strict:
            all_passed = all_passed and all(not r.has_warnings for r in results)
        sys.exit(0 if all_passed else 1)

    overall_pass = print_summary(results, strict=args.strict)
    sys.exit(0 if overall_pass else 1)


if __name__ == "__main__":
    main()
