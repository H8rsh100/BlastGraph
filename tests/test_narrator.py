"""Test suite for narrative generator ensuring non-empty output and anti-hallucination validation."""
import pytest
from narrator.generate_narrative import generate_narrative


def test_generate_narrative_non_empty_and_valid():
    """Test narrative generation returns non-empty string referencing path node IDs."""
    path = [
        ("aws_s3_bucket.my_data", "aws_s3_bucket", "Public S3 Bucket ACL"),
        ("aws_iam_role.app_role", "aws_iam_role", "Overly Permissive Wildcard IAM Policy")
    ]
    
    narrative = generate_narrative(path)
    
    assert narrative is not None
    assert isinstance(narrative, str)
    assert len(narrative.strip()) > 0
    
    # Assert resource names from input path appear in narrative output
    assert "aws_s3_bucket.my_data" in narrative
    assert "aws_iam_role.app_role" in narrative
