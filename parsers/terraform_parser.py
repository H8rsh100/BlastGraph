"""Terraform HCL manifest parser module."""


def parse_terraform_dir(dir_path: str) -> list[dict]:
    """Parse Terraform files in directory and return normalized resource dicts.
    
    Args:
        dir_path: Path to directory containing .tf files.
        
    Returns:
        List of resource dicts containing resource_type, name, attributes, references.
    """
    return []
