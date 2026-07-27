"""Kubernetes YAML manifest parser using PyYAML with logging."""
import logging
import os
from typing import Any
import yaml

logger = logging.getLogger(__name__)


def extract_k8s_references(doc: dict[str, Any]) -> list[str]:
    """Extract referenced resource identifiers from Kubernetes manifest spec/metadata."""
    refs = set()
    kind = doc.get("kind", "")
    spec = doc.get("spec", {}) or {}

    def _scan_volumes_and_envs(container_spec: dict) -> None:
        for env in container_spec.get("env", []) or []:
            if isinstance(env, dict):
                val_from = env.get("valueFrom", {}) or {}
                if "secretKeyRef" in val_from:
                    refs.add(f"Secret.{val_from['secretKeyRef'].get('name')}")
                if "configMapKeyRef" in val_from:
                    refs.add(f"ConfigMap.{val_from['configMapKeyRef'].get('name')}")
        
        for env_from in container_spec.get("envFrom", []) or []:
            if isinstance(env_from, dict):
                if "secretRef" in env_from:
                    refs.add(f"Secret.{env_from['secretRef'].get('name')}")
                if "configMapRef" in env_from:
                    refs.add(f"ConfigMap.{env_from['configMapRef'].get('name')}")

    containers = []
    if kind in ("Pod",):
        containers = spec.get("containers", []) or []
    elif kind in ("Deployment", "StatefulSet", "DaemonSet", "Job"):
        template_spec = (spec.get("template", {}) or {}).get("spec", {}) or {}
        containers = template_spec.get("containers", []) or []
        service_account = template_spec.get("serviceAccountName")
        if service_account:
            refs.add(f"ServiceAccount.{service_account}")

    for container in containers:
        if isinstance(container, dict):
            _scan_volumes_and_envs(container)

    if kind == "Service":
        selector = spec.get("selector", {}) or {}
        for k, v in selector.items():
            refs.add(f"PodSelector.{k}={v}")

    return sorted(list(refs))


def parse_k8s_dir(dir_path: str) -> list[dict[str, Any]]:
    """Parse Kubernetes YAML manifests in a directory and return normalized resource dicts."""
    resources = []
    if not os.path.exists(dir_path):
        logger.warning(f"Kubernetes directory does not exist: {dir_path}")
        return resources

    logger.info(f"Scanning for Kubernetes YAML files in: {dir_path}")
    for root, _, files in os.walk(dir_path):
        for file in files:
            if file.endswith((".yaml", ".yml")):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        docs = yaml.safe_load_all(f)
                        for doc in docs:
                            if isinstance(doc, dict) and "kind" in doc:
                                kind = doc.get("kind", "Unknown")
                                metadata = doc.get("metadata", {}) or {}
                                name = metadata.get("name", "unnamed")
                                spec = doc.get("spec", {}) or doc
                                refs = extract_k8s_references(doc)
                                
                                resources.append({
                                    "resource_type": str(kind),
                                    "name": str(name),
                                    "attributes": spec if isinstance(spec, dict) else {},
                                    "references": refs,
                                    "source_file": file_path
                                })
                except Exception as e:
                    logger.error(f"Error parsing Kubernetes YAML {file_path}: {e}")
                    continue

    logger.info(f"Successfully parsed {len(resources)} Kubernetes resources.")
    return resources
