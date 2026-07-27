"""Misconfiguration detector rules for Infrastructure-as-Code resources."""
import json
from typing import Any, Optional


def check_public_s3(resource: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Check if S3 bucket or access block permits public access.

    Args:
        resource: Parsed resource dictionary.

    Returns:
        Violation dictionary if vulnerable, else None.
    """
    res_type = resource.get("resource_type", "")
    attrs = resource.get("attributes", {}) or {}

    if res_type == "aws_s3_bucket":
        acl = attrs.get("acl", "")
        if isinstance(acl, list) and acl:
            acl = acl[0]
        if acl in ("public-read", "public-read-write"):
            return {
                "rule_id": "RULE-S3-001",
                "title": "Public S3 Bucket ACL",
                "severity": "HIGH",
                "description": f"S3 Bucket '{resource.get('name')}' is configured with public ACL '{acl}'."
            }

    elif res_type == "aws_s3_bucket_public_access_block":
        block_public_acls = attrs.get("block_public_acls", True)
        block_public_policy = attrs.get("block_public_policy", True)
        if block_public_acls is False or block_public_policy is False:
            return {
                "rule_id": "RULE-S3-002",
                "title": "Disabled S3 Public Access Block",
                "severity": "HIGH",
                "description": f"S3 Public Access Block '{resource.get('name')}' leaves public access unblocked."
            }

    return None


def check_open_security_group(resource: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Check if Security Group opens ingress to 0.0.0.0/0.

    Args:
        resource: Parsed resource dictionary.

    Returns:
        Violation dictionary if vulnerable, else None.
    """
    res_type = resource.get("resource_type", "")
    attrs = resource.get("attributes", {}) or {}

    if res_type in ("aws_security_group", "aws_security_group_rule"):
        ingress_list = attrs.get("ingress", [])
        if isinstance(ingress_list, dict):
            ingress_list = [ingress_list]

        for rule in ingress_list:
            if isinstance(rule, dict):
                cidr_blocks = rule.get("cidr_blocks", [])
                if isinstance(cidr_blocks, list):
                    # Check list elements or nested lists
                    flat_cidrs = []
                    for item in cidr_blocks:
                        if isinstance(item, list):
                            flat_cidrs.extend(item)
                        else:
                            flat_cidrs.append(str(item))
                    if "0.0.0.0/0" in flat_cidrs or '["0.0.0.0/0"]' in flat_cidrs:
                        return {
                            "rule_id": "RULE-SG-001",
                            "title": "Unrestricted Security Group Ingress 0.0.0.0/0",
                            "severity": "CRITICAL",
                            "description": f"Security Group '{resource.get('name')}' grants ingress access to 0.0.0.0/0."
                        }

        # Check standalone rule cidr_blocks
        cidr_blocks = attrs.get("cidr_blocks", [])
        if isinstance(cidr_blocks, list) and "0.0.0.0/0" in cidr_blocks:
            return {
                "rule_id": "RULE-SG-001",
                "title": "Unrestricted Security Group Ingress 0.0.0.0/0",
                "severity": "CRITICAL",
                "description": f"Security Group rule '{resource.get('name')}' grants ingress access to 0.0.0.0/0."
            }

    return None


def check_root_pod(resource: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Check if Kubernetes Pod container is permitted to run as root user.

    Args:
        resource: Parsed resource dictionary.

    Returns:
        Violation dictionary if vulnerable, else None.
    """
    res_type = resource.get("resource_type", "")
    attrs = resource.get("attributes", {}) or {}

    if res_type in ("Pod", "Deployment", "StatefulSet", "DaemonSet"):
        pod_spec = attrs
        if res_type != "Pod":
            pod_spec = (attrs.get("template", {}) or {}).get("spec", {}) or {}

        sec_context = pod_spec.get("securityContext", {}) or {}
        run_as_non_root = sec_context.get("runAsNonRoot", False)
        run_as_user = sec_context.get("runAsUser", None)

        if run_as_non_root is not True or run_as_user == 0:
            return {
                "rule_id": "RULE-K8S-001",
                "title": "Kubernetes Pod Running as Root",
                "severity": "HIGH",
                "description": f"Kubernetes resource '{resource.get('name')}' does not enforce runAsNonRoot: true."
            }

    return None


def check_wildcard_iam(resource: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Check if IAM Policy grants full wildcard '*' permissions.

    Args:
        resource: Parsed resource dictionary.

    Returns:
        Violation dictionary if vulnerable, else None.
    """
    res_type = resource.get("resource_type", "")
    attrs = resource.get("attributes", {}) or {}

    if res_type in ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_group_policy"):
        policy_str = str(attrs.get("policy", ""))
        try:
            if policy_str.startswith("{"):
                policy_obj = json.loads(policy_str)
                statements = policy_obj.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]
                for stmt in statements:
                    action = stmt.get("Action", "")
                    res = stmt.get("Resource", "")
                    if action == "*" or res == "*" or "*" in action:
                        return {
                            "rule_id": "RULE-IAM-001",
                            "title": "Overly Permissive Wildcard IAM Policy",
                            "severity": "HIGH",
                            "description": f"IAM Policy '{resource.get('name')}' grants wildcard '*' permissions."
                        }
        except Exception:
            pass

        if '"*"' in policy_str or "'*'" in policy_str or 'Action": "*"' in policy_str:
            return {
                "rule_id": "RULE-IAM-001",
                "title": "Overly Permissive Wildcard IAM Policy",
                "severity": "HIGH",
                "description": f"IAM Policy '{resource.get('name')}' contains wildcard '*' specification."
            }

    return None


ALL_RULES = [
    check_public_s3,
    check_open_security_group,
    check_root_pod,
    check_wildcard_iam
]
