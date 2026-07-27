"""Graph builder module to construct NetworkX dependency graph from resources."""
from typing import Any
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
            # Direct match on node_id
            if ref in node_map:
                graph.add_edge(source_id, ref, relationship="references")
            else:
                # Check for partial matches or add target node if missing
                matching_nodes = [nid for nid in node_map if nid.endswith(f".{ref}") or ref.endswith(nid)]
                if matching_nodes:
                    for target_id in matching_nodes:
                        graph.add_edge(source_id, target_id, relationship="references")
                else:
                    # Add implicit node for unresolved reference
                    graph.add_node(ref, resource_type="ExternalReference", name=ref, attributes={}, references=[], source_file="")
                    graph.add_edge(source_id, ref, relationship="references")

    return graph
