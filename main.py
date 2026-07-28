"""Main entry point for BlastGraph analyzer with chain reasoning and narrative generation."""
import argparse
import json
import logging
import os
import sys
from typing import Any
import networkx as nx

from config import Config
from parsers.terraform_parser import parse_terraform_dir
from parsers.k8s_parser import parse_k8s_dir
from graph.builder import build_resource_graph, export_graph_json, export_graph_png
from detectors.rules import ALL_RULES
from docs_ingest.ingest import ingest_cis_docs, retrieve_cis_guidance_for_resource
from chain.reasoner import find_attack_paths, score_path
from narrator.generate_narrative import generate_narrative

logging.basicConfig(
    level=getattr(logging, Config.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("BlastGraph")


def run_detectors(graph: nx.DiGraph, chroma_dir: str = "./chroma_db") -> list[dict[str, Any]]:
    """Walk every node in the graph, execute misconfig rules, and attach CIS guidance snippets."""
    violations = []
    logger.info("Evaluating detector rules across graph nodes.")

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

    logger.info(f"Finished rule evaluation. Found {len(violations)} total violations.")
    return violations


def analyze_directory(target_dir: str, chroma_dir: str = "./chroma_dir", export_viz: bool = True) -> dict[str, Any]:
    """Run end-to-end BlastGraph analysis on a target directory."""
    logger.info(f"Starting BlastGraph analysis for target directory: {target_dir}")
    tf_resources = parse_terraform_dir(target_dir)
    k8s_resources = parse_k8s_dir(target_dir)

    all_resources = tf_resources + k8s_resources
    logger.info(f"Total resources parsed: {len(all_resources)}")

    graph = build_resource_graph(all_resources)

    if export_viz and len(graph.nodes) > 0:
        json_path = export_graph_json(graph)
        png_path = export_graph_png(graph)
        logger.info(f"Graph visualizations exported to {json_path} and {png_path}")

    ingest_cis_docs(chroma_dir=chroma_dir)

    violations = run_detectors(graph, chroma_dir=chroma_dir)

    logger.info("Executing chain reasoning to discover attack paths.")
    attack_paths = find_attack_paths(graph, violations, max_hops=4, top_n=10)
    logger.info(f"Discovered {len(attack_paths)} top attack paths across the resource graph.")

    narratives = []
    for idx, path in enumerate(attack_paths, 1):
        narrative_text = generate_narrative(path, chroma_dir=chroma_dir)
        narratives.append({
            "path_index": idx,
            "score": score_path(path),
            "path": path,
            "narrative": narrative_text
        })

    return {
        "resource_count": len(all_resources),
        "node_count": len(graph.nodes),
        "edge_count": len(graph.edges),
        "violations": violations,
        "attack_paths": attack_paths,
        "narratives": narratives
    }


def main():
    """CLI entry point for BlastGraph."""
    parser = argparse.ArgumentParser(description="BlastGraph - Infra-as-Code Blast Radius Analyzer")
    parser.add_argument("dir", nargs="?", default=".", help="Directory containing IaC manifests")
    parser.add_argument("--chroma-dir", default=Config.CHROMA_DB_DIR, help="Path to Chroma DB directory")
    args = parser.parse_args()

    results = analyze_directory(args.dir, chroma_dir=args.chroma_dir)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
