"""Terraform HCL manifest parser stub with precise function signatures."""
from typing import Any


def parse_terraform_dir(dir_path: str) -> list[dict[str, Any]]:
    """Parse Terraform files in directory and return normalized resource dicts.

    Args:
        dir_path: Path to directory containing .tf files.

    Returns:
        List of resource dicts, each formatted as:
        {
            "resource_type": str,
            "name": str,
            "attributes": dict,
            "references": list[str]
        }
    """
    raise NotImplementedError("parse_terraform_dir is not implemented yet.")
