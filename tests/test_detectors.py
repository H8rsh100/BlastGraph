"""Test suite covering detector rules with passing and failing sample fixtures."""
from detectors.rules import (
    check_public_s3,
    check_open_security_group,
    check_root_pod,
    check_wildcard_iam
)


def test_check_public_s3_violates():
    """Test public S3 bucket rule triggers on public ACL."""
    resource = {
        "resource_type": "aws_s3_bucket",
        "name": "public_bucket",
        "attributes": {"acl": "public-read"}
    }
    violation = check_public_s3(resource)
    assert violation is not None
    assert violation["rule_id"] == "RULE-S3-001"
    assert violation["severity"] == "HIGH"


def test_check_public_s3_passes():
    """Test private S3 bucket passes public S3 rule."""
    resource = {
        "resource_type": "aws_s3_bucket",
        "name": "private_bucket",
        "attributes": {"acl": "private"}
    }
    violation = check_public_s3(resource)
    assert violation is None


def test_check_open_security_group_violates():
    """Test security group open to 0.0.0.0/0 triggers violation."""
    resource = {
        "resource_type": "aws_security_group",
        "name": "open_sg",
        "attributes": {
            "ingress": [
                {"cidr_blocks": ["0.0.0.0/0"], "from_port": 22, "to_port": 22}
            ]
        }
    }
    violation = check_open_security_group(resource)
    assert violation is not None
    assert violation["rule_id"] == "RULE-SG-001"
    assert violation["severity"] == "CRITICAL"


def test_check_open_security_group_passes():
    """Test restricted security group passes open SG rule."""
    resource = {
        "resource_type": "aws_security_group",
        "name": "restricted_sg",
        "attributes": {
            "ingress": [
                {"cidr_blocks": ["10.0.0.0/16"], "from_port": 22, "to_port": 22}
            ]
        }
    }
    violation = check_open_security_group(resource)
    assert violation is None


def test_check_root_pod_violates():
    """Test Kubernetes pod without runAsNonRoot triggers root pod rule."""
    resource = {
        "resource_type": "Pod",
        "name": "root_pod",
        "attributes": {
            "securityContext": {"runAsNonRoot": False}
        }
    }
    violation = check_root_pod(resource)
    assert violation is not None
    assert violation["rule_id"] == "RULE-K8S-001"


def test_check_root_pod_passes():
    """Test Kubernetes pod with runAsNonRoot: true passes root pod rule."""
    resource = {
        "resource_type": "Pod",
        "name": "secure_pod",
        "attributes": {
            "securityContext": {"runAsNonRoot": True}
        }
    }
    violation = check_root_pod(resource)
    assert violation is None


def test_check_wildcard_iam_violates():
    """Test IAM policy with wildcard '*' triggers wildcard rule."""
    resource = {
        "resource_type": "aws_iam_policy",
        "name": "admin_policy",
        "attributes": {
            "policy": '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}'
        }
    }
    violation = check_wildcard_iam(resource)
    assert violation is not None
    assert violation["rule_id"] == "RULE-IAM-001"


def test_check_wildcard_iam_passes():
    """Test restricted IAM policy passes wildcard rule."""
    resource = {
        "resource_type": "aws_iam_policy",
        "name": "read_only_policy",
        "attributes": {
            "policy": '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::mybucket/*"}]}'
        }
    }
    violation = check_wildcard_iam(resource)
    assert violation is None
