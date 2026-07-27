"""Terraform HCL manifest parser using python-hcl2 with logging."""
import logging
import os
import re
from typing import Any
import hcl2

logger = logging.getLogger(__name__)


def extract_references(data: Any) -> list[str]:
    """Recursively search data for Terraform resource reference strings (e.g. aws_s3_bucket.main.id)."""
    refs = set()
    ref_pattern = re.compile(r'\b([a-zA-Z0-9_]+)\.([a-zA-Z0-9_\-]+)\.([a-zA-Z0-9_\-]+)\b')

    def _search(obj: Any) -> None:
        if isinstance(obj, str):
            for match in ref_pattern.finditer(obj):
                res_type, res_name, _ = match.groups()
                if res_type not in ("var", "local", "module", "data"):
                    refs.add(f"{res_type}.{res_name}")
        elif isinstance(obj, dict):
            for v in obj.values():
                _search(v)
        elif isinstance(obj, list):
            for item in obj:
                _search(item)

    _search(data)
    return sorted(list(refs))


def parse_terraform_dir(dir_path: str) -> list[dict[str, Any]]:
    """Parse Terraform files in directory and return normalized resource dicts."""
    resources = []
    if not os.path.exists(dir_path):
        logger.warning(f"Terraform directory does not exist: {dir_path}")
        return resources

    logger.info(f"Scanning for Terraform .tf files in: {dir_path}")
    for root, _, files in os.walk(dir_path):
        for file in files:
            if file.endswith(".tf"):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        parsed = hcl2.load(f)
                    
                    resource_blocks = parsed.get("resource", [])
                    for res_entry in resource_blocks:
                        if not isinstance(res_entry, dict):
                            continue
                        for res_type, name_entry in res_entry.items():
                            if isinstance(name_entry, list):
                                for item in name_entry:
                                    if isinstance(item, dict):
                                        for res_name, attrs in item.items():
                                            refs = extract_references(attrs)
                                            resources.append({
                                                "resource_type": str(res_type),
                                                "name": str(res_name),
                                                "attributes": attrs if isinstance(attrs, dict) else {},
                                                "references": refs,
                                                "source_file": file_path
                                            })
                            elif isinstance(name_entry, dict):
                                for res_name, attrs in name_entry.items():
                                    refs = extract_references(attrs)
                                    resources.append({
                                        "resource_type": str(res_type),
                                        "name": str(res_name),
                                        "attributes": attrs if isinstance(attrs, dict) else {},
                                        "references": refs,
                                        "source_file": file_path
                                    })
                except Exception as e:
                    logger.error(f"Error parsing Terraform file {file_path}: {e}")
                    continue

    logger.info(f"Successfully parsed {len(resources)} Terraform resources.")
    return resources
