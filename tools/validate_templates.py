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

LEGACY_TEMPLATES = {
    "ai-tools/chatgpt_account_suspended.html",
    "ai-tools/copilot_license_suspended.html",
    "ai-tools/education/ai_tools_phishing_education.html",
    "cloud-services/dropbox_share.html",
    "cloud-services/education/cloud_services_education.html",
    "cloud-services/google_drive.html",
    "collaboration/education/collaboration_education.html",
    "collaboration/slack_notification.html",
    "collaboration/teams_alert.html",
    "collaboration/zoom_meeting.html",
    "corporate/breaking_news.html",
    "corporate/education/corporate_education.html",
    "corporate/travel_agency.html",
    "delivery-shipping/dhl_package.html",
    "delivery-shipping/education/delivery_phishing_education.html",
    "delivery-shipping/package_pickup.html",
    "e-signature/adobe_sign.html",
    "e-signature/docusign_signature.html",
    "e-signature/education/esignature_education.html",
    "education/education/education_phishing_education.html",
    "education/financial_aid_urgent.html",
    "education/student_portal_lockout.html",
    "entertainment/education/entertainment_education.html",
    "entertainment/spotify_account.html",
    "entertainment/starbucks_gift.html",
    "financial/education/financial_education.html",
    "financial/skype_payment.html",
    "financial/wire_transfer.html",
    "government/better_business.html",
    "government/crime_report.html",
    "government/education/government_education.html",
    "government/fdic_survey.html",
    "healthcare/education/healthcare_education.html",
    "healthcare/hipaa_compliance_alert.html",
    "healthcare/insurance_verification.html",
    "healthcare/patient_portal_security.html",
    "hospitality/education/hospitality_education.html",
    "hospitality/hotel_reservation_confirm.html",
    "hr-payroll/benefits_enrollment.html",
    "hr-payroll/education/hr_payroll_education.html",
    "hr-payroll/payroll_direct_deposit.html",
    "identity/education/identity_education.html",
    "identity/okta_verification.html",
    "it-security/dropbox_share.html",
    "it-security/education/it_security_education.html",
    "it-security/email_issues.html",
    "it-security/email_size_limit.html",
    "it-security/mailbox_compromised.html",
    "it-security/system_update.html",
    "it-security/webmail_upgrade.html",
    "itsm/education/itsm_education.html",
    "itsm/servicenow_ticket.html",
    "latam-portuguese/education/latam_portuguese_education.html",
    "latam-portuguese/helpdesk_ti.html",
    "latam-portuguese/microsoft365_corporativo.html",
    "latam-portuguese/notificacao_bancaria.html",
    "latam-portuguese/onboarding_rh.html",
    "latam-portuguese/receita_federal.html",
    "legal/case_document_sharing.html",
    "legal/education/legal_education.html",
    "manufacturing/education/manufacturing_education.html",
    "manufacturing/supplier_portal_update.html",
    "microsoft/education/microsoft_education.html",
    "microsoft/microsoft_security.html",
    "quishing/education/quishing_education.html",
    "quishing/qr_code_mfa.html",
    "quishing/qr_code_wifi.html",
    "retail/education/retail_education.html",
    "retail/loyalty_rewards_expiring.html",
    "smishing/bank_alert_sms.html",
    "smishing/education/smishing_education.html",
    "smishing/package_delivery_sms.html",
    "social-media/education/social_media_education.html",
    "social-media/linkedin_reminder.html",
    "technology/api_key_expiration.html",
    "technology/education/technology_education.html",
    "utilities/education/utilities_education.html",
    "utilities/power_outage_credit.html"
}

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

        # Additional fields for Issue #38 compatibility & accessibility checks
        self.html_lang = None
        self.style_blocks = []
        self.inline_styles = []
        self.images = []
        self.links = []
        self.link_stylesheets = []
        self.in_style = False
        self.current_style_data = []
        self.in_link = False
        self.current_link_attrs = {}
        self.current_link_data = []

    def handle_decl(self, decl):
        if decl.lower().startswith("doctype"):
            self.has_doctype = True

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        tag_lower = tag.lower()

        if tag_lower == "html":
            self.has_html = True
            self.html_lang = attrs_dict.get("lang")
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
        elif tag_lower == "style":
            self.in_style = True
            self.current_style_data = []
        elif tag_lower == "link":
            rel = attrs_dict.get("rel", "").lower()
            href = attrs_dict.get("href", "")
            if rel == "stylesheet" and href:
                self.link_stylesheets.append(href)
        elif tag_lower == "img":
            self.images.append(attrs_dict)
            if self.in_link:
                # If an image has an alt text inside a link, it counts as discernible text for the link.
                alt = attrs_dict.get("alt", "").strip()
                if alt:
                    self.current_link_data.append(alt)
        elif tag_lower == "a":
            self.in_link = True
            self.current_link_attrs = attrs_dict
            self.current_link_data = []

        if "style" in attrs_dict:
            self.inline_styles.append(attrs_dict["style"])

        if tag_lower not in ("br", "hr", "img", "input", "meta", "link", "area", "base"):
            self.tag_stack.append(tag_lower)

    def handle_endtag(self, tag):
        tag_lower = tag.lower()
        if tag_lower == "title":
            self._in_title = False
        elif tag_lower == "style":
            self.in_style = False
            self.style_blocks.append("".join(self.current_style_data))
        elif tag_lower == "a" and self.in_link:
            self.in_link = False
            self.links.append({
                "attrs": self.current_link_attrs,
                "text": "".join(self.current_link_data).strip()
            })

        if self.tag_stack and self.tag_stack[-1] == tag_lower:
            self.tag_stack.pop()

    def handle_data(self, data):
        if self._in_title:
            self.title_text += data
        if self.in_style:
            self.current_style_data.append(data)
        if self.in_link:
            self.current_link_data.append(data)


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


def check_html_structure(content: str, result: ValidationResult) -> Optional[HTMLStructureChecker]:
    """Check basic HTML structure validity."""
    checker = HTMLStructureChecker()
    try:
        checker.feed(content)
    except Exception as e:
        result.errors.append(f"HTML parse error: {e}")
        return None

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

    return checker


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
    """Check that metadata.json exists and references this template."""
    metadata_path = template_path.parent / "metadata.json"

    if not metadata_path.exists():
        result.warnings.append(
            "No metadata.json found in this directory — consider adding template metadata"
        )
        return

    try:
        with open(metadata_path) as f:
            metadata = json.load(f)
    except json.JSONDecodeError as e:
        result.errors.append(f"metadata.json is invalid JSON: {e}")
        return

    # Check if this template is referenced in metadata
    templates = metadata.get("templates", [])
    template_filenames = [t.get("filename", "") for t in templates]

    if template_path.name not in template_filenames:
        result.warnings.append(
            f"Template '{template_path.name}' is not listed in metadata.json"
        )
        return

    # Validate metadata fields for this template
    for tmpl in templates:
        if tmpl.get("filename") == template_path.name:
            required_fields = ["name", "attack_vector", "difficulty", "gophish_variables", "suggested_subject_lines"]
            for field_name in required_fields:
                if not tmpl.get(field_name):
                    result.warnings.append(f"metadata.json missing '{field_name}' for this template")

            valid_difficulties = {"beginner", "intermediate", "advanced"}
            if tmpl.get("difficulty") not in valid_difficulties:
                result.errors.append(
                    f"Invalid difficulty '{tmpl.get('difficulty')}' — must be one of: {valid_difficulties}"
                )


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


def check_style_layouts(style_content: str, allowed_rules: set, result: ValidationResult):
    # Remove CSS comments in style_content first to avoid false positives inside comments
    clean_style = re.sub(r'/\*.*?\*/', '', style_content, flags=re.DOTALL)
    
    # Helper to check and add non-duplicate warning
    def add_warning(msg: str):
        if msg not in result.warnings:
            result.warnings.append(msg)
            
    # 1. position
    if "layout-position" not in allowed_rules:
        if re.search(r'\bposition\s*:', clean_style, re.IGNORECASE):
            add_warning(
                "Unsupported email layout pattern 'position' found. "
                "Email clients have poor support for absolute/fixed positioning. Encourage table-based layouts."
            )
            
    # 2. flex
    if "layout-flex" not in allowed_rules:
        if (re.search(r'\bdisplay\s*:\s*(inline-)?flex\b', clean_style, re.IGNORECASE) or
            re.search(r'\bflex\s*:', clean_style, re.IGNORECASE) or
            re.search(r'\bflex-[a-zA-Z-]+\s*:', clean_style, re.IGNORECASE)):
            add_warning(
                "Unsupported email layout pattern 'flex' found. "
                "Flexbox is not supported by many email clients (especially Outlook). Encourage table-based layouts."
            )

    # 3. grid
    if "layout-grid" not in allowed_rules:
        if (re.search(r'\bdisplay\s*:\s*(inline-)?grid\b', clean_style, re.IGNORECASE) or
            re.search(r'\bgrid\s*:', clean_style, re.IGNORECASE) or
            re.search(r'\bgrid-[a-zA-Z-]+\s*:', clean_style, re.IGNORECASE)):
            add_warning(
                "Unsupported email layout pattern 'grid' found. "
                "CSS Grid is not supported by many email clients (especially Outlook). Encourage table-based layouts."
            )

    # 4. float
    if "layout-float" not in allowed_rules:
        if re.search(r'\bfloat\s*:\s*(left|right)\b', clean_style, re.IGNORECASE):
            add_warning(
                "Unsupported email layout pattern 'float' found. "
                "Float-heavy layouts are prone to rendering issues. Encourage table-based layouts."
            )


def extract_selectors(css_text: str) -> List[str]:
    # Remove comments
    css_text = re.sub(r'/\*.*?\*/', '', css_text, flags=re.DOTALL)
    selectors = []
    
    current_selector = []
    brace_level = 0
    in_media_query = False
    
    i = 0
    n = len(css_text)
    while i < n:
        char = css_text[i]
        if char == '{':
            if brace_level == 0:
                selector_str = "".join(current_selector).strip()
                if selector_str.startswith('@'):
                    if selector_str.lower().startswith('@media') or selector_str.lower().startswith('@supports'):
                        in_media_query = True
                else:
                    for sel in selector_str.split(','):
                        sel = sel.strip()
                        if sel:
                            selectors.append(sel)
            elif in_media_query and brace_level == 1:
                selector_str = "".join(current_selector).strip()
                for sel in selector_str.split(','):
                    sel = sel.strip()
                    if sel:
                        selectors.append(sel)
            
            brace_level += 1
            current_selector = []
        elif char == '}':
            brace_level -= 1
            if brace_level == 0:
                in_media_query = False
            current_selector = []
        else:
            if brace_level == 0 or (in_media_query and brace_level == 1):
                current_selector.append(char)
        i += 1
    return selectors


def check_css_selectors(style_content: str, allowed_rules: set, result: ValidationResult):
    if "css-selector" in allowed_rules:
        return
        
    selectors = extract_selectors(style_content)
    for selector in selectors:
        reasons = []
        if ">" in selector:
            reasons.append("child combinator ('>')")
        if "+" in selector:
            reasons.append("adjacent sibling combinator ('+')")
        if "~" in selector:
            reasons.append("general sibling combinator ('~')")
        if "[" in selector:
            reasons.append("attribute selector ('[...]')")
        if "::" in selector:
            reasons.append("pseudo-element ('::')")
        
        # Check pseudo-classes (single colon, but not double colon)
        clean_selector = selector.replace("::", "__pseudo_element__")
        pseudo_classes = re.findall(r':([a-zA-Z0-9_-]+)', clean_selector)
        unsupported_pseudos = {
            "hover", "focus", "active", "visited", 
            "nth-child", "nth-of-type", "first-child", "last-child", "only-child",
            "not", "checked", "disabled", "enabled", "target", "empty"
        }
        for pc in pseudo_classes:
            pc_lower = pc.lower()
            if pc_lower in unsupported_pseudos or pc_lower.startswith("nth-"):
                reasons.append(f"pseudo-class ':{pc}'")
        
        if reasons:
            reasons_str = ", ".join(reasons)
            msg = (
                f"Unsupported CSS selector '{selector}' inside <style> block: uses {reasons_str}. "
                f"Outlook and other email clients have poor support for these selectors."
            )
            if msg not in result.warnings:
                result.warnings.append(msg)


def check_email_client_compatibility_and_accessibility(content: str, checker: HTMLStructureChecker, result: ValidationResult, is_education: bool):
    """Run email compatibility and accessibility checks (GitHub Issue #38)."""
    # Parse <!-- validate:allow <rules> --> comments
    allowed_rules = set()
    for match in re.findall(r'<!--\s*validate:allow\s+([^>]+?)\s*-->', content):
        for rule in match.split():
            allowed_rules.add(rule.strip())

    # Helper to check if a warning should be added
    def add_warn(rule_name: str, message: str):
        if rule_name not in allowed_rules:
            if message not in result.warnings:
                result.warnings.append(message)

    # ── 1. Accessibility Checks (HTML Lang & Link text) ────────────────────────
    # These apply to all files (templates and education pages)
    if "html-lang" not in allowed_rules:
        # Check if lang is present and has a value
        if checker.has_html and (not checker.html_lang or not checker.html_lang.strip()):
            add_warn("html-lang", "Missing 'lang' attribute on <html> tag")

    if "link-text" not in allowed_rules:
        for link in checker.links:
            href = link["attrs"].get("href", "[no href]")
            link_text = link["text"]
            has_label = (
                bool(link_text) or
                "aria-label" in link["attrs"] or
                "aria-labelledby" in link["attrs"] or
                "title" in link["attrs"]
            )
            if not has_label:
                add_warn("link-text", f"<a> link is missing discernible text or accessibility label (href: '{href}')")

    # ── 2. Images ─────────────────────────────────────────────────────────────
    # alt is accessibility, width/height is email-compat (layout shift prevention)
    for img in checker.images:
        src = img.get("src", "[no src]")
        if "img-alt" not in allowed_rules:
            if "alt" not in img:
                add_warn("img-alt", f"<img> tag is missing 'alt' attribute (src: '{src}')")
        if not is_education and "img-size" not in allowed_rules:
            if "width" not in img or "height" not in img:
                add_warn("img-size", f"<img> tag is missing HTML 'width' or 'height' attribute (src: '{src}')")

    # ── 3. Email-Client Compatibility Checks (Only on Phishing Email Templates) ─────
    if not is_education:
        # Layout checks (inline styles)
        for inline_style in checker.inline_styles:
            check_style_layouts(inline_style, allowed_rules, result)

        # Layout & Selector checks (style blocks)
        for style_block in checker.style_blocks:
            check_style_layouts(style_block, allowed_rules, result)
            check_css_selectors(style_block, allowed_rules, result)

        # External stylesheet links check
        if "css-link" not in allowed_rules:
            for href in checker.link_stylesheets:
                if href.startswith(("http://", "https://", "//")):
                    add_warn(
                        "css-link",
                        f"External stylesheet link found: '{href}'. "
                        f"External stylesheets are not supported by many email clients; use <style> blocks or inline CSS."
                    )

        # Dark mode color-scheme handling check
        if "dark-mode" not in allowed_rules:
            # Check if colors are defined in any styles
            color_pattern = re.compile(r'\b(color|background-color|background)\s*:', re.IGNORECASE)
            colors_defined = False
            for inline_style in checker.inline_styles:
                if color_pattern.search(inline_style):
                    colors_defined = True
                    break
            if not colors_defined:
                for style_block in checker.style_blocks:
                    if color_pattern.search(style_block):
                        colors_defined = True
                        break

            if colors_defined:
                # Check for prefers-color-scheme or color-scheme / supported-color-schemes in meta
                has_dark_handling = (
                    "prefers-color-scheme" in content.lower() or
                    'name="color-scheme"' in content.lower() or
                    "name='color-scheme'" in content.lower() or
                    'name="supported-color-schemes"' in content.lower() or
                    "name='supported-color-schemes'" in content.lower()
                )
                if not has_dark_handling:
                    add_warn(
                        "dark-mode",
                        "Text or background colors are defined, but no dark mode handling "
                        "(prefers-color-scheme or color-scheme meta tags) was found. "
                        "Consider adding support for dark mode readers."
                    )


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
    path_rel = str(file_path.relative_to(ROOT))
    is_legacy = path_rel in LEGACY_TEMPLATES

    checker = check_html_structure(content, result)
    if checker is not None and not is_legacy:
        check_email_client_compatibility_and_accessibility(content, checker, result, is_education)

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
