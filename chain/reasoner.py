"""Attack path chain reasoner module implementing graph traversal."""
from typing import Any
import networkx as nx


def find_attack_paths(graph: nx.DiGraph, violations: list[dict[str, Any]], max_hops: int = 4) -> list[list[tuple[str, str, str]]]:
    """Find attack paths passing through multiple violated nodes within max_hops.

    Args:
        graph: NetworkX resource DiGraph.
        violations: List of violation dicts from detectors.
        max_hops: Maximum path hop length.

    Returns:
        List of attack paths, where each path is a list of (node_id, resource_type, violation_title) tuples.
    """
    # Create mapping of node_id -> list of violation dicts
    node_violations: dict[str, list[dict[str, Any]]] = {}
    for v in violations:
        nid = v.get("node_id")
        if nid:
            if nid not in node_violations:
                node_violations[nid] = []
            node_violations[nid].append(v)

    violated_nodes = set(node_violations.keys())
    if len(violated_nodes) < 2:
        # Need at least 2 violated nodes to form a chain
        return []

    raw_paths = []

    # Traverse graph starting from every violated node
    for start_node in violated_nodes:
        for target_node in violated_nodes:
            if start_node == target_node:
                continue
            if nx.has_path(graph, start_node, target_node):
                try:
                    paths = nx.all_simple_paths(graph, source=start_node, target=target_node, cutoff=max_hops)
                    for path in paths:
                        # Check if path contains at least 2 violated nodes
                        v_nodes_in_path = [n for n in path if n in violated_nodes]
                        if len(v_nodes_in_path) >= 2:
                            raw_paths.append(path)
                except Exception:
                    continue

    return raw_paths
