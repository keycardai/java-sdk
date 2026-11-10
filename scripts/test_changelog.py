"""Unit tests for scripts/changelog.py.

Run with:

    python3 -m unittest discover -s scripts -p 'test_*.py'
"""

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import changelog


class RepoTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())

    def tearDown(self) -> None:
        shutil.rmtree(self.root)

    def write(self, cz_version: str, gradle_line: str | None) -> None:
        (self.root / ".cz.toml").write_text(f'[tool.commitizen]\nversion = "{cz_version}"\n')
        if gradle_line is not None:
            (self.root / "gradle.properties").write_text(f"group=ai.keycard\n{gradle_line}\norg.gradle.caching=true\n")


class CheckDriftTests(RepoTestCase):
    def test_matching_versions_report_no_drift(self) -> None:
        self.write("0.3.0", "version=0.3.0")
        self.assertIsNone(changelog.check_version_drift(self.root))

    def test_hand_edited_gradle_version_is_caught(self) -> None:
        self.write("0.3.0", "version=0.4.0")
        self.assertEqual(
            changelog.check_version_drift(self.root),
            {"file": "gradle.properties", "cz_version": "0.3.0", "file_version": "0.4.0"},
        )

    def test_snapshot_suffix_is_drift(self) -> None:
        self.write("0.3.0", "version=0.3.0-SNAPSHOT")
        self.assertIsNotNone(changelog.check_version_drift(self.root))

    def test_missing_gradle_properties_is_drift_not_a_crash(self) -> None:
        self.write("0.3.0", None)
        self.assertEqual(changelog.check_version_drift(self.root)["file_version"], None)

    def test_spaces_around_the_equals_sign_are_read(self) -> None:
        self.write("0.3.0", "version = 0.3.0")
        self.assertIsNone(changelog.check_version_drift(self.root))


class ExtractPackageFromTagTests(unittest.TestCase):
    def test_resolves_a_v_tag(self) -> None:
        self.assertEqual(
            changelog.extract_package_from_tag("v1.2.3"),
            {"tag": "v1.2.3", "version": "1.2.3", "package_name": "java-sdk", "package_dir": "."},
        )

    def test_strips_refs_tags_prefix(self) -> None:
        self.assertEqual(changelog.extract_package_from_tag("refs/tags/v0.1.0")["version"], "0.1.0")

    def test_other_tags_are_rejected(self) -> None:
        for tag in ("1.2.3", "v1.2", "v1.2.3-rc1", "0.1.0-keycardai-oauth", ""):
            with self.subTest(tag=tag), self.assertRaises(Exception):
                changelog.extract_package_from_tag(tag)


class HasUnreleasedChangesTests(unittest.TestCase):
    @mock.patch.object(changelog, "run_command", return_value=(0, "## Unreleased\n\n### Feat\n\n- device grant", ""))
    def test_unreleased_section_with_entries_counts_as_changed(self, _run) -> None:
        self.assertTrue(changelog.has_unreleased_changes())
        self.assertEqual(changelog.detect_changes(), [changelog.PACKAGE])

    @mock.patch.object(changelog, "run_command", return_value=(0, "## Unreleased\n\n### Feat\n\n## v0.1.0 (2026-11-11)", ""))
    def test_empty_unreleased_section_counts_as_unchanged(self, _run) -> None:
        self.assertFalse(changelog.has_unreleased_changes())
        self.assertEqual(changelog.detect_changes(), [])

    @mock.patch.object(changelog, "run_command", return_value=(0, "## v0.1.0 (2026-11-11)\n\n- x", ""))
    def test_changelog_without_an_unreleased_section_counts_as_unchanged(self, _run) -> None:
        self.assertFalse(changelog.has_unreleased_changes())


class RealConfigTests(unittest.TestCase):
    def test_repository_has_no_drift(self) -> None:
        self.assertIsNone(changelog.check_version_drift())


if __name__ == "__main__":
    unittest.main()
