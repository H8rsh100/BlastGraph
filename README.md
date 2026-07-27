# BlastGraph: Infra-as-Code Blast Radius Analyzer

BlastGraph parses your real Terraform HCL and Kubernetes YAML manifests into a resource dependency graph, cross-references CIS Benchmarks and cloud security docs via local RAG (Chroma DB), and flags security misconfigurations across your infrastructure graph.

Unlike simple flat linters, BlastGraph models infrastructure dependencies as a directed graph, laying the groundwork for multi-hop attack path reasoning.

---

## Architecture

```
[Terraform/K8s files] --> [Parser] --> [Resource Graph (NetworkX)]
                                              |
[CIS Benchmarks + cloud docs] --> [Chroma Vector DB] --> [RAG retrieval]
                                              |
                          [Misconfig Detector] --> flags individual issues
```

---

## Features (Day 1 Scope)

- **Terraform HCL Parsing**: Parses `.tf` files into normalized resource representations using `python-hcl2` and extracts cross-resource interpolation references.
- **Kubernetes YAML Parsing**: Parses Kubernetes manifests (Pods, Deployments, Services, Secrets) using `PyYAML` and tracks service account / volume / label references.
- **Resource Dependency Graph**: Constructs a directed graph (`NetworkX DiGraph`) with resource nodes and reference relationship edges.
- **Graph Export & Visualization**: Exports dependency graphs to standard JSON (`blast_graph.json`) and renders PNG diagrams (`blast_graph.png`).
- **CIS Benchmark RAG Ingestion**: Automatically chunks, embeds, and indexes CIS security benchmark guidance in a local persistent Chroma DB (`chroma_db/`).
- **Misconfiguration Detection Rules**:
  - `RULE-S3-001`: Public S3 Bucket ACL (`public-read`, `public-read-write`)
  - `RULE-SG-001`: Unrestricted Security Group Ingress (`0.0.0.0/0`)
  - `RULE-K8S-001`: Kubernetes Pod running as root user (`runAsNonRoot: false`)
  - `RULE-IAM-001`: Overly permissive wildcard IAM policies (`*`)

---

## Installation & Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/H8rsh100/BlastGraph.git
   cd BlastGraph
   ```

2. **Install dependencies**:
   ```bash
   python -m pip install -r requirements.txt
   ```

3. **Environment setup**:
   Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

---

## Usage

Run BlastGraph against any folder containing Terraform or Kubernetes manifests:

```bash
python main.py /path/to/iac/directory
```

### Running Unit Tests
```bash
python -m pytest tests/
```

---

## Coming in Day 2

- **Attack-Path Chain Reasoning**: Graph traversal algorithms to link individual misconfigurations into multi-hop attack vectors.
- **LLM Attack Path Narratives**: Auto-generated attack narratives explaining how an adversary could exploit chained misconfigurations.
- **Fix Prioritization**: Graph centrality ranking to prioritize fixes that collapse the maximum number of attack paths.
- **REST API & Web UI**: FastAPI service and interactive dashboard.

---

## License

[MIT License](file:///c:/PROJECTS/BlastGraph/LICENSE)
