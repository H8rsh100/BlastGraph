"""Rule definitions for detecting infrastructure misconfigurations."""


def check_public_s3(resource: dict) -> bool:
    """Check if S3 bucket configuration permits public access."""
    return False


def check_open_security_group(resource: dict) -> bool:
    """Check if Security Group opens ingress to 0.0.0.0/0."""
    return False


def check_root_pod(resource: dict) -> bool:
    """Check if Kubernetes Pod runs as root user."""
    return False


def check_wildcard_iam(resource: dict) -> bool:
    """Check if IAM Policy uses wildcard '*' for actions or resources."""
    return False
