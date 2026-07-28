"""Test suite for chain reasoning module covering graph traversal, path scoring, and deduplication."""
import networkx as nx
import pytest

from chain.reasoner import find_attack_paths, score_path, dedupe_and_rank_paths


@pytest.fixture
def synthetic_infra_graph():
    """Create a synthetic 4-resource infrastructure dependency graph."""
    graph = nx.DiGraph()
    
    graph.add_node("aws_security_group.open_sg", resource_type="aws_security_group", name="open_sg")
    graph.add_node("aws_instance.web_app", resource_type="aws_instance", name="web_app")
    graph.add_node("aws_iam_role.app_role", resource_type="aws_iam_role", name="app_role")
    graph.add_node("aws_s3_bucket.data_bucket", resource_type="aws_s3_bucket", name="data_bucket")

    # Edges: open_sg -> web_app -> app_role -> data_bucket
    graph.add_edge("aws_security_group.open_sg", "aws_instance.web_app", relationship="references")
    graph.add_edge("aws_instance.web_app", "aws_iam_role.app_role", relationship="references")
    graph.add_edge("aws_iam_role.app_role", "aws_s3_bucket.data_bucket", relationship="references")

    return graph


@pytest.fixture
def synthetic_violations():
    """Create sample violations for synthetic resources."""
    return [
        {
            "node_id": "aws_security_group.open_sg",
            "rule_id": "RULE-SG-001",
            "title": "Unrestricted Security Group Ingress 0.0.0.0/0",
            "severity": "CRITICAL"
        },
        {
            "node_id": "aws_iam_role.app_role",
            "rule_id": "RULE-IAM-001",
            "title": "Overly Permissive Wildcard IAM Policy",
            "severity": "HIGH"
        },
        {
            "node_id": "aws_s3_bucket.data_bucket",
            "rule_id": "RULE-S3-001",
            "title": "Public S3 Bucket ACL",
            "severity": "HIGH"
        }
    ]


def test_find_attack_paths_discovers_chains(synthetic_infra_graph, synthetic_violations):
    """Test that chain reasoner discovers multi-hop attack paths."""
    paths = find_attack_paths(synthetic_infra_graph, synthetic_violations, max_hops=4, top_n=5)
    
    assert len(paths) >= 1
    longest_path = paths[0]
    
    node_ids = [step[0] for step in longest_path]
    assert node_ids[0] == "aws_security_group.open_sg"
    assert "aws_s3_bucket.data_bucket" in node_ids


def test_score_path():
    """Test path risk score calculation."""
    sample_path = [
        ("aws_security_group.open_sg", "aws_security_group", "Unrestricted Security Group Ingress 0.0.0.0/0"),
        ("aws_s3_bucket.data_bucket", "aws_s3_bucket", "Public S3 Bucket ACL")
    ]
    score = score_path(sample_path)
    assert score > 0.0
    assert score == 34.0


def test_dedupe_and_rank_paths():
    """Test path deduplication filters subpaths and ranks by score."""
    p1 = [
        ("n1", "aws_sg", "Unrestricted 0.0.0.0/0"),
        ("n2", "aws_iam", "Wildcard IAM"),
        ("n3", "aws_s3", "Public S3")
    ]
    p2 = [
        ("n1", "aws_sg", "Unrestricted 0.0.0.0/0"),
        ("n2", "aws_iam", "Wildcard IAM")
    ]
    
    result = dedupe_and_rank_paths([p1, p2], top_n=5)
    assert len(result) == 1
    assert result[0] == p1
