"""End-to-end integration test suite verifying BlastGraph pipeline against sample IaC repo."""
import os
import pytest

from main import analyze_directory
from report import build_report


def test_end_to_end_pipeline():
    """Test full pipeline execution against sample IaC fixtures directory."""
    fixture_dir = os.path.join("tests", "fixtures", "sample_iac")
    assert os.path.exists(fixture_dir)

    results = analyze_directory(fixture_dir, export_viz=False)
    report = build_report(results)

    assert "summary" in report
    assert "violations" in report
    assert "attack_paths" in report
    assert "narratives" in report
    assert "prioritized_fixes" in report

    # Verify violations flagged
    assert report["summary"]["violation_count"] >= 3
    assert len(report["violations"]) >= 3

    # Verify prioritized fixes populated
    assert len(report["prioritized_fixes"]) >= 3
