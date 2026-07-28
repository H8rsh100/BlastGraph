"""Attack path chain reasoner module with path scoring logic."""
from typing import Any
import networkx as nx


def score_path(path: list[tuple[str, str, str]]) -> float:
    """Calculate severity score for an attack path based on hop length and violation severity.

    Shorter paths with higher severity violations yield higher risk scores.

    Args:
        path: List of (node_id, resource_type, violation_title) tuples.

    Returns:
        Float score representing risk magnitude.
    """
    if not path:
        return 0.0

    severity_score = 0.0
    for _, _, v_title in path:
        v_title_lower = v_title.lower()
        if "critical" in v_title_lower or "0.0.0.0/0" in v_title_lower:
            severity_score += 10.0
        elif "public" in v_title_lower or "root" in v_title_lower or "wildcard" in v_title_lower or "high" in v_title_lower:
            severity_score += 7.0
        elif v_title != "Intermediate Link":
            severity_score += 4.0
        else:
            severity_score += 1.0

    # Shorter paths are more direct and higher risk (hop multiplier)
    hops = max(1, len(path) - 1)
    hop_multiplier = 1.0 + (1.0 / hops)

    return round(severity_score * hop_multiplier, 2)


def find_attack_paths(graph: nx.DiGraph, violations: list[dict[str, Any]], max_hops: int = 4) -> list[list[tuple[str, str, str]]]:
    """Find attack paths passing through multiple violated nodes within max_hops.

    Args:
        graph: NetworkX resource DiGraph.
        violations: List of violation dicts from detectors.
        max_hops: Maximum path hop length.

    Returns:
        List of attack paths, where each path is an ordered list of (node_id, resource_type, violation_title) tuples.
    """
    node_violations: dict[str, list[dict[str, Any]]] = {}
    for v in violations:
        nid = v.get("node_id")
        if nid:
            if nid not in node_violations:
                node_violations[nid] = []
            node_violations[nid].append(v)

    violated_nodes = set(node_violations.keys())
    if len(violated_nodes) < 2:
        return []

    formatted_paths = []

    for start_node in violated_nodes:
        for target_node in violated_nodes:
            if start_node == target_node:
                continue
            if nx.has_path(graph, start_node, target_node):
                try:
                    paths = nx.all_simple_paths(graph, source=start_node, target=target_node, cutoff=max_hops)
                    for raw_path in paths:
                        v_nodes_in_path = [n for n in raw_path if n in violated_nodes]
                        if len(v_nodes_in_path) >= 2:
                            path_tuples = []
                            for nid in raw_path:
                                node_attrs = graph.nodes[nid] if nid in graph.nodes else {}
                                res_type = node_attrs.get("resource_type", "Unknown")
                                
                                if nid in node_violations:
                                    v_titles = ", ".join([v.get("title", "Misconfiguration") for v in node_violations[nid]])
                                else:
                                    v_titles = "Intermediate Link"

                                path_tuples.append((nid, res_type, v_titles))
                            
                            formatted_paths.append(path_tuples)
                except Exception:
                    continue

    return formatted_paths
