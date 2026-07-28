"""Attack path chain reasoner module with logging."""
import logging
from typing import Any
import networkx as nx

logger = logging.getLogger(__name__)


def score_path(path: list[tuple[str, str, str]]) -> float:
    """Calculate severity score for an attack path based on hop length and violation severity."""
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

    hops = max(1, len(path) - 1)
    hop_multiplier = 1.0 + (1.0 / hops)

    return round(severity_score * hop_multiplier, 2)


def dedupe_and_rank_paths(paths: list[list[tuple[str, str, str]]], top_n: int = 10) -> list[list[tuple[str, str, str]]]:
    """Deduplicate overlapping paths and return top_n highest scoring attack paths."""
    if not paths:
        return []

    scored_paths = [(p, score_path(p)) for p in paths]
    scored_paths.sort(key=lambda x: x[1], reverse=True)

    unique_paths = []
    seen_node_sequences = set()

    for path, score in scored_paths:
        node_seq = tuple(t[0] for t in path)
        if node_seq in seen_node_sequences:
            continue

        is_subpath = False
        for accepted in unique_paths:
            acc_seq = [t[0] for t in accepted]
            if len(node_seq) < len(acc_seq):
                for i in range(len(acc_seq) - len(node_seq) + 1):
                    if acc_seq[i:i + len(node_seq)] == list(node_seq):
                        is_subpath = True
                        break
            if is_subpath:
                break

        if not is_subpath:
            seen_node_sequences.add(node_seq)
            unique_paths.append(path)
            logger.info(f"Accepted attack path (score={score}): {[t[0] for t in path]}")

        if len(unique_paths) >= top_n:
            break

    return unique_paths


def find_attack_paths(
    graph: nx.DiGraph,
    violations: list[dict[str, Any]],
    max_hops: int = 4,
    top_n: int = 10
) -> list[list[tuple[str, str, str]]]:
    """Find attack paths passing through multiple violated nodes within max_hops."""
    logger.info(f"Starting attack path discovery across graph (max_hops={max_hops})")
    node_violations: dict[str, list[dict[str, Any]]] = {}
    for v in violations:
        nid = v.get("node_id")
        if nid:
            if nid not in node_violations:
                node_violations[nid] = []
            node_violations[nid].append(v)

    violated_nodes = set(node_violations.keys())
    if len(violated_nodes) < 2:
        logger.info(f"Insufficient violated nodes ({len(violated_nodes)}) to construct multi-hop attack chains.")
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

    logger.info(f"Discovered {len(formatted_paths)} raw candidate attack paths before deduplication.")
    return dedupe_and_rank_paths(formatted_paths, top_n=top_n)
