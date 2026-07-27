"""Main entry point for BlastGraph analyzer."""
import argparse
import json
import os
import sys
from typing import Any
import networkx as nx

from parsers.terraform_parser import parse_terraform_dir
from parsers.k8s_parser import parse_k8s_dir
from graph.builder import build_resource_graph, export_graph_json, export_graph_png
from detectors.rules import ALL_RULES
from docs_ingest.ingest import ingest_cis_docs, retrieve_cis_guidance_for_resource


def run_detectors(graph: nx.DiGraph, chroma_dir: str = "./chroma_db") -> list[dict[str, Any]]:
    """Walk every node in the graph, execute misconfig rules, and attach CIS guidance snippets.

    Args:
        graph: NetworkX DiGraph instance representing infrastructure resources.
        chroma_dir: Directory path for Chroma DB vector store.

    Returns:
        List of detected security violations with CIS references attached.
    """
    violations = []

    for node_id, node_attrs in graph.nodes(data=True):
        res_type = node_attrs.get("resource_type", "")
        name = node_attrs.get("name", "")
        attributes = node_attrs.get("attributes", {}) or {}

        if res_type == "ExternalReference":
            continue

        resource = {
            "resource_type": res_type,
            "name": name,
            "attributes": attributes
        }

        for rule_fn in ALL_RULES:
            vulnerability = rule_fn(resource)
            if vulnerability:
                # Retrieve matching CIS guidance
                guidance = retrieve_cis_guidance_for_resource(
                    resource_type=res_type,
                    issue=vulnerability.get("title", ""),
                    chroma_dir=chroma_dir
                )
                vulnerability["node_id"] = node_id
                vulnerability["resource_type"] = res_type
                vulnerability["resource_name"] = name
                vulnerability["source_file"] = node_attrs.get("source_file", "")
                vulnerability["cis_guidance"] = guidance
                violations.append(vulnerability)

    return violations


def analyze_directory(target_dir: str, chroma_dir: str = "./chroma_db", export_viz: bool = True) -> dict[str, Any]:
    """Run end-to-end BlastGraph analysis on a target directory.

    Args:
        target_dir: Directory containing Terraform or K8s files.
        chroma_dir: Chroma DB storage location.
        export_viz: Whether to export graph visualization files.

    Returns:
        Analysis summary dict with graph stats and detected violations.
    """
    print(f"[*] Parsing Terraform manifests in: {target_dir}")
    tf_resources = parse_terraform_dir(target_dir)

    print(f"[*] Parsing Kubernetes manifests in: {target_dir}")
    k8s_resources = parse_k8s_dir(target_dir)

    all_resources = tf_resources + k8s_resources
    print(f"[*] Total parsed resources: {len(all_resources)}")

    print("[*] Building resource dependency graph...")
    graph = build_resource_graph(all_resources)
    print(f"[*] Graph constructed: {len(graph.nodes)} nodes, {len(graph.edges)} edges")

    if export_viz and len(graph.nodes) > 0:
        json_path = export_graph_json(graph)
        png_path = export_graph_png(graph)
        print(f"[*] Exported graph JSON to: {json_path}")
        print(f"[*] Exported graph PNG visualization to: {png_path}")

    # Ensure CIS docs ingested if available
    ingest_cis_docs(chroma_dir=chroma_dir)

    print("[*] Running misconfiguration detector rules...")
    violations = run_detectors(graph, chroma_dir=chroma_dir)
    print(f"[!] Total security violations flagged: {len(violations)}")

    return {
        "resource_count": len(all_resources),
        "node_count": len(graph.nodes),
        "edge_count": len(graph.edges),
        "violations": violations
    }


def main():
    """CLI entry point for BlastGraph."""
    parser = argparse.ArgumentParser(description="BlastGraph - Infra-as-Code Blast Radius Analyzer")
    parser.add_argument("dir", nargs="?", default=".", help="Directory containing IaC manifests")
    parser.add_argument("--chroma-dir", default="./chroma_db", help="Path to Chroma DB directory")
    args = parser.parse_args()

    results = analyze_directory(args.dir, chroma_dir=args.chroma_dir)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
