"""Report module for formatting and exporting structured JSON analysis reports."""
import json
import os
from typing import Any


def build_report(
    analysis_results: dict[str, Any]
) -> dict[str, Any]:
    """Format raw analysis results into structured report JSON.

    Args:
        analysis_results: Output dictionary from main analysis pipeline.

    Returns:
        Structured report dictionary.
    """
    violations = analysis_results.get("violations", [])
    attack_paths = analysis_results.get("attack_paths", [])
    narratives = analysis_results.get("narratives", [])
    prioritized_fixes = analysis_results.get("prioritized_fixes", [])

    return {
        "summary": {
            "resource_count": analysis_results.get("resource_count", 0),
            "node_count": analysis_results.get("node_count", 0),
            "edge_count": analysis_results.get("edge_count", 0),
            "violation_count": len(violations),
            "attack_path_count": len(attack_paths)
        },
        "violations": violations,
        "attack_paths": attack_paths,
        "narratives": narratives,
        "prioritized_fixes": prioritized_fixes
    }


def save_report(report_data: dict[str, Any], output_path: str = "blast_graph_report.json") -> str:
    """Save report dictionary to a JSON file.

    Args:
        report_data: Report dictionary.
        output_path: Target JSON file path.

    Returns:
        Absolute filepath of saved JSON report.
    """
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)
    return os.path.abspath(output_path)
