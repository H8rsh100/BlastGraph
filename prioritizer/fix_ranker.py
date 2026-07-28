"""Fix ranker module performing counterfactual simulation to rank remediation fixes."""
import logging
from typing import Any
import networkx as nx

from chain.reasoner import find_attack_paths

logger = logging.getLogger(__name__)


def rank_fixes(
    graph: nx.DiGraph,
    violations: list[dict[str, Any]],
    max_hops: int = 4
) -> list[dict[str, Any]]:
    """Rank violations by the number of attack paths eliminated if that single violation is remediated.

    Args:
        graph: NetworkX resource DiGraph.
        violations: Original list of detected violations.
        max_hops: Maximum hop distance for path finding.

    Returns:
        List of violation rank dicts sorted descending by paths_eliminated.
    """
    if not violations:
        return []

    original_paths = find_attack_paths(graph, violations, max_hops=max_hops, top_n=50)
    original_count = len(original_paths)
    logger.info(f"Baseline attack path count for fix simulation: {original_count}")

    ranked_fixes = []

    for v in violations:
        # Counterfactual simulation: remove this specific violation
        simulated_violations = [item for item in violations if item != v]
        remaining_paths = find_attack_paths(graph, simulated_violations, max_hops=max_hops, top_n=50)
        paths_eliminated = max(0, original_count - len(remaining_paths))

        ranked_fixes.append({
            "node_id": v.get("node_id"),
            "rule_id": v.get("rule_id"),
            "title": v.get("title"),
            "severity": v.get("severity"),
            "resource_type": v.get("resource_type"),
            "resource_name": v.get("resource_name"),
            "source_file": v.get("source_file"),
            "paths_eliminated": paths_eliminated,
            "remaining_paths": len(remaining_paths)
        })

    # Sort descending by paths_eliminated
    ranked_fixes.sort(key=lambda x: (x["paths_eliminated"], x["severity"] == "CRITICAL", x["severity"] == "HIGH"), reverse=True)

    return ranked_fixes
