"""Graph builder module to construct and export NetworkX dependency graphs."""
import json
import os
from typing import Any
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt
import networkx as nx


def get_node_id(resource: dict[str, Any]) -> str:
    """Generate a standard unique node identifier for a resource."""
    res_type = resource.get("resource_type", "Unknown")
    name = resource.get("name", "unnamed")
    return f"{res_type}.{name}"


def build_resource_graph(resources: list[dict[str, Any]]) -> nx.DiGraph:
    """Build a NetworkX DiGraph from parsed resource dictionaries.

    Nodes represent individual IaC resources.
    Directed edges represent reference/dependency relationships (Resource A -> Resource B).

    Args:
        resources: List of resource dictionaries.

    Returns:
        networkx.DiGraph instance.
    """
    graph = nx.DiGraph()

    # Step 1: Add all nodes
    node_map = {}
    for res in resources:
        node_id = get_node_id(res)
        node_map[node_id] = res
        graph.add_node(
            node_id,
            resource_type=res.get("resource_type"),
            name=res.get("name"),
            attributes=res.get("attributes", {}),
            references=res.get("references", []),
            source_file=res.get("source_file", "")
        )

    # Step 2: Add directed edges based on references
    for res in resources:
        source_id = get_node_id(res)
        refs = res.get("references", [])
        for ref in refs:
            if ref in node_map:
                graph.add_edge(source_id, ref, relationship="references")
            else:
                matching_nodes = [nid for nid in node_map if nid.endswith(f".{ref}") or ref.endswith(nid)]
                if matching_nodes:
                    for target_id in matching_nodes:
                        graph.add_edge(source_id, target_id, relationship="references")
                else:
                    graph.add_node(ref, resource_type="ExternalReference", name=ref, attributes={}, references=[], source_file="")
                    graph.add_edge(source_id, ref, relationship="references")

    return graph


def export_graph_json(graph: nx.DiGraph, output_path: str = "blast_graph.json") -> str:
    """Export the NetworkX graph to a JSON file format.

    Args:
        graph: NetworkX DiGraph instance.
        output_path: Path to output JSON file.

    Returns:
        Absolute path to created JSON file.
    """
    data = nx.node_link_data(graph)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return os.path.abspath(output_path)


def export_graph_png(graph: nx.DiGraph, output_path: str = "blast_graph.png") -> str:
    """Render and save a simple visualization of the graph using matplotlib.

    Args:
        graph: NetworkX DiGraph instance.
        output_path: Path to output PNG image file.

    Returns:
        Absolute path to created PNG file.
    """
    plt.figure(figsize=(12, 8))
    pos = nx.spring_layout(graph, k=0.5, seed=42)

    nx.draw_networkx_nodes(graph, pos, node_size=1500, node_color="#4f46e5", alpha=0.9)
    nx.draw_networkx_edges(graph, pos, arrowstyle="->", arrowsize=15, edge_color="#9ca3af", width=1.5)
    nx.draw_networkx_labels(graph, pos, font_size=8, font_color="#ffffff", font_weight="bold")

    plt.title("BlastGraph - Infrastructure Resource Dependency Graph", fontsize=14, pad=15)
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close()

    return os.path.abspath(output_path)
