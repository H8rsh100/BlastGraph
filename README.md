# BlastGraph: Infra-as-Code Blast Radius Analyzer

BlastGraph is an Infrastructure-as-Code (IaC) security analyzer that parses Terraform HCL and Kubernetes YAML manifests, builds a resource dependency graph using NetworkX, cross-references CIS Benchmarks via local RAG (Chroma DB), performs multi-hop **chain reasoning** to discover attack paths, generates plain-English **attack narratives**, and ranks remediation fixes by the number of attack paths collapsed.

---

## Full System Architecture

```
[Terraform/K8s files] --> [Parsers] --> [Resource Graph (NetworkX)]
                                              |
[CIS Benchmarks] ---------> [Chroma DB] ----> [Misconfig Detectors]
                                              |
                                     [Chain Reasoner] (DFS/BFS graph traversal)
                                              |
                                     [LLM Attack Narrator] (RAG grounded)
                                              |
                                     [Fix Prioritizer] (Counterfactual simulation)
                                              |
                                     [Structured Report JSON]
```

---

## Features

- **Terraform & Kubernetes Parsing**: Parses `.tf` HCL files using `python-hcl2` and `.yaml` Kubernetes manifests using `PyYAML`.
- **Graph Construction & Export**: Builds a `NetworkX DiGraph` linking resources via reference edges, exporting visualizations to `blast_graph.json` and `blast_graph.png`.
- **CIS Benchmark RAG**: Ingests and chunks CIS security benchmark guidance into local persistent Chroma DB (`chroma_db/`).
- **Misconfiguration Detection**:
  - `RULE-S3-001` / `RULE-S3-002`: Public S3 bucket ACLs & disabled public access blocks
  - `RULE-SG-001`: Unrestricted Security Group ingress (`0.0.0.0/0`)
  - `RULE-K8S-001`: Kubernetes Pod running as root user (`runAsNonRoot: false`)
  - `RULE-IAM-001`: Overly permissive wildcard IAM policies (`*`)
- **Chain Reasoning**: Discovers multi-hop attack paths linking multiple violated infrastructure resources.
- **Attack Path Scoring & Deduplication**: Scores paths by hop distance and severity weights, filtering subpaths.
- **LLM Attack Narratives**: Generates plain-English attack narratives grounded in retrieved CIS guidance.
- **Counterfactual Fix Prioritization**: Simulates remediation of each individual violation and ranks fixes by the total count of attack paths collapsed.

---

## Installation & Setup

1. **Clone repository**:
   ```bash
   git clone https://github.com/H8rsh100/BlastGraph.git
   cd BlastGraph
   ```

2. **Install requirements**:
   ```bash
   python -m pip install -r requirements.txt
   ```

3. **Configure environment**:
   ```bash
   cp .env.example .env
   ```

---

## Usage Examples

Run the full end-to-end BlastGraph analysis pipeline against any IaC folder:

```bash
python main.py --repo tests/fixtures/sample_iac
```

### Running Unit & Integration Tests
```bash
python -m pytest tests/
```

---

## Sample JSON Report Output

```json
{
  "summary": {
    "resource_count": 5,
    "node_count": 5,
    "edge_count": 3,
    "violation_count": 4,
    "attack_path_count": 1
  },
  "violations": [...],
  "attack_paths": [
    [
      ["aws_security_group.web_sg", "aws_security_group", "Unrestricted Security Group Ingress 0.0.0.0/0"],
      ["aws_s3_bucket.public_bucket", "aws_s3_bucket", "Public S3 Bucket ACL"]
    ]
  ],
  "narratives": [
    {
      "path_index": 1,
      "score": 34.0,
      "narrative": "An attacker initially gains access through resource 'aws_security_group.web_sg' due to Unrestricted Ingress 0.0.0.0/0. From there, the adversary pivots to 'aws_s3_bucket.public_bucket' exploiting Public S3 Bucket ACL."
    }
  ],
  "prioritized_fixes": [
    {
      "node_id": "aws_security_group.web_sg",
      "rule_id": "RULE-SG-001",
      "title": "Unrestricted Security Group Ingress 0.0.0.0/0",
      "paths_eliminated": 1,
      "remaining_paths": 0
    }
  ]
}
```

---

## License

[MIT License](file:///c:/PROJECTS/BlastGraph/LICENSE)
