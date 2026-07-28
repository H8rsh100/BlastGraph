"""Prompt templates for LLM attack path narrative generation."""

NARRATIVE_SYSTEM_PROMPT = """You are a cloud security architect analyzing an infrastructure attack path.
Given an attack path sequence of resources and their security misconfigurations, along with CIS guidance for each step, write a 3-5 sentence plain-English narrative describing how an attacker could exploit this chain.

CRITICAL CONSTRAINTS:
1. Use ONLY the resource names, resource types, and CIS guidance provided in the prompt.
2. Do NOT invent or mention any external resource names, CVEs, tools, or details not provided in the input context.
3. Keep the tone concise, factual, and focused on security impact.
"""


def format_narrative_prompt(path: list[tuple[str, str, str]], cis_guidance_list: list[str]) -> str:
    """Format path sequence and CIS guidance into a structured user prompt.

    Args:
        path: List of (node_id, resource_type, violation_title) tuples.
        cis_guidance_list: List of retrieved CIS benchmark text snippets.

    Returns:
        Formatted prompt string.
    """
    path_str_lines = []
    for idx, (node_id, res_type, v_title) in enumerate(path, 1):
        path_str_lines.append(f"Step {idx}: Resource '{node_id}' ({res_type}) - Violation: {v_title}")

    path_description = "\n".join(path_str_lines)

    guidance_description = "None"
    if cis_guidance_list:
        guidance_description = "\n".join([f"- {g}" for g in cis_guidance_list if g])

    return f"""ATTACK PATH SEQUENCE:
{path_description}

RELEVANT CIS BENCHMARK GUIDANCE:
{guidance_description}

Write a 3-5 sentence attack narrative explaining this chain:"""
