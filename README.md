# BlastGraph: Infra-as-Code Blast Radius Analyzer

BlastGraph parses your real Terraform and Kubernetes manifests into a resource dependency graph, cross-references CIS Benchmarks and cloud security docs via RAG, and flags security misconfigurations across your infrastructure graph.

## Architecture Overview
```
[Terraform/K8s files] --> [Parser] --> [Resource Graph (NetworkX)]
                                              |
[CIS Benchmarks + cloud docs] --> [Chroma Vector DB] --> [RAG retrieval]
                                              |
                          [Misconfig Detector] --> flags individual issues
```

## Features (Day 1 Scope)
- Parsing of HCL Terraform (`.tf`) and Kubernetes YAML manifests into unified resource representations.
- Dependency graph generation powered by NetworkX.
- Misconfiguration detection rules (Public S3 buckets, open Security Groups 0.0.0.0/0, root-running Pods, wildcard IAM policies).
- Local RAG integration using Chroma DB for contextual CIS Benchmark guidance.

## License
MIT License - see [LICENSE](file:///c:/PROJECTS/BlastGraph/LICENSE) for details.
