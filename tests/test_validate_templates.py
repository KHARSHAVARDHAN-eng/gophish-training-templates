import unittest
import json
import tempfile
import re
from pathlib import Path
import sys

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import validate_templates
from validate_templates import (
    ValidationResult,
    check_metadata,
)

class TestMetadataValidation(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        # Create a mock template file
        self.template_path = self.temp_path / "test_template.html"
        self.template_path.write_text("<html></html>", encoding="utf-8")
        
        self.result = ValidationResult(path=str(self.template_path))
        
        # Valid baseline metadata dict
        self.valid_metadata = {
            "category": self.temp_path.name,
            "industry": "Cross-industry",
            "description": "Test description",
            "gophish_version_tested": "0.12.1",
            "last_updated": "2026-06-27",
            "templates": [
                {
                    "filename": "test_template.html",
                    "name": "Test Template",
                    "attack_vector": "credential_harvest",
                    "difficulty": "intermediate",
                    "estimated_click_rate": "30-50%",
                    "gophish_variables": ["{{.URL}}", "{{.Tracker}}"],
                    "suggested_subject_lines": ["Urgent alert"],
                    "education_page": "education/test_edu.html",
                    "tags": ["test"],
                    "notes": "Some test deployment notes."
                }
            ]
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def write_metadata(self, data):
        meta_path = self.temp_path / "metadata.json"
        meta_path.write_text(json.dumps(data), encoding="utf-8")

    def test_valid_metadata_passes(self):
        self.write_metadata(self.valid_metadata)
        check_metadata(self.template_path, self.result)
        self.assertEqual(len(self.result.errors), 0, f"Errors found: {self.result.errors}")

    def test_missing_metadata_file(self):
        # Do not write metadata file
        check_metadata(self.template_path, self.result)
        self.assertTrue(any("No metadata.json found" in err for err in self.result.errors))

    def test_invalid_json(self):
        meta_path = self.temp_path / "metadata.json"
        meta_path.write_text("invalid json {", encoding="utf-8")
        check_metadata(self.template_path, self.result)
        self.assertTrue(any("metadata.json is invalid JSON" in err for err in self.result.errors))

    def test_category_mismatch(self):
        self.valid_metadata["category"] = "wrong-category-name"
        self.write_metadata(self.valid_metadata)
        check_metadata(self.template_path, self.result)
        self.assertTrue(any("does not match directory name" in err for err in self.result.errors))

    def test_missing_version(self):
        del self.valid_metadata["gophish_version_tested"]
        self.write_metadata(self.valid_metadata)
        check_metadata(self.template_path, self.result)
        self.assertTrue(any("missing top-level field 'gophish_version_tested'" in err for err in self.result.errors))

    def test_invalid_last_updated_format(self):
        self.valid_metadata["last_updated"] = "2026/06/27"  # non-ISO format
        self.write_metadata(self.valid_metadata)
        check_metadata(self.template_path, self.result)
        self.assertTrue(any("must be in YYYY-MM-DD ISO format" in err for err in self.result.errors))

    def test_missing_required_template_field(self):
        # Remove 'notes' field
        del self.valid_metadata["templates"][0]["notes"]
        self.write_metadata(self.valid_metadata)
        check_metadata(self.template_path, self.result)
        self.assertTrue(any("missing required field 'notes'" in err for err in self.result.errors))

    def test_invalid_difficulty_enum(self):
        self.valid_metadata["templates"][0]["difficulty"] = "expert"
        self.write_metadata(self.valid_metadata)
        check_metadata(self.template_path, self.result)
        self.assertTrue(any("Invalid difficulty" in err for err in self.result.errors))

    def test_invalid_attack_vector_enum(self):
        self.valid_metadata["templates"][0]["attack_vector"] = "spear_phish"
        self.write_metadata(self.valid_metadata)
        check_metadata(self.template_path, self.result)
        self.assertTrue(any("Invalid attack_vector" in err for err in self.result.errors))

    def test_invalid_click_rate_format(self):
        self.valid_metadata["templates"][0]["estimated_click_rate"] = "high"
        self.write_metadata(self.valid_metadata)
        check_metadata(self.template_path, self.result)
        self.assertTrue(any("Invalid estimated_click_rate" in err for err in self.result.errors))

    def test_missing_gophish_variables(self):
        # Missing {{.Tracker}}
        self.valid_metadata["templates"][0]["gophish_variables"] = ["{{.URL}}"]
        self.write_metadata(self.valid_metadata)
        check_metadata(self.template_path, self.result)
        self.assertTrue(any("missing required variable '{{.Tracker}}'" in err for err in self.result.errors))

    def test_empty_suggested_subject_lines(self):
        self.valid_metadata["templates"][0]["suggested_subject_lines"] = []
        self.write_metadata(self.valid_metadata)
        check_metadata(self.template_path, self.result)
        self.assertTrue(any("must contain at least one entry" in err for err in self.result.errors))

if __name__ == "__main__":
    unittest.main()
