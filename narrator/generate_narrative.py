"""Narrative generator module combining CIS RAG context with LLM generation."""
import logging
from typing import Optional

from config import Config
from docs_ingest.ingest import retrieve_cis_guidance_for_resource
from narrator.prompt_templates import NARRATIVE_SYSTEM_PROMPT, format_narrative_prompt

logger = logging.getLogger(__name__)


def generate_fallback_narrative(path: list[tuple[str, str, str]], cis_guidance: list[str]) -> str:
    """Generate a deterministic, grounded narrative fallback when LLM API key is not configured."""
    steps_narrative = []
    for idx, (node_id, res_type, v_title) in enumerate(path, 1):
        if idx == 1:
            steps_narrative.append(f"An attacker initially gains access through resource '{node_id}' ({res_type}) due to {v_title}.")
        elif idx == len(path):
            steps_narrative.append(f"Finally, the attack reaches resource '{node_id}' ({res_type}), exploiting {v_title} to compromise critical assets.")
        else:
            steps_narrative.append(f"From there, the adversary pivots to '{node_id}' ({res_type}) leveraging {v_title}.")

    guidance_summary = ""
    if cis_guidance:
        guidance_summary = f" CIS benchmark guidelines highlight: {cis_guidance[0]}"

    return " ".join(steps_narrative) + guidance_summary


def generate_narrative(path: list[tuple[str, str, str]], chroma_dir: str = "./chroma_db") -> str:
    """Generate a plain-English attack narrative for a given attack path.

    Args:
        path: List of (node_id, resource_type, violation_title) tuples.
        chroma_dir: Directory path for Chroma DB.

    Returns:
        Generated narrative string.
    """
    if not path:
        return "No attack path specified."

    # Retrieve CIS guidance per step
    cis_guidance_list = []
    for node_id, res_type, v_title in path:
        snippets = retrieve_cis_guidance_for_resource(res_type, v_title, chroma_dir=chroma_dir, top_k=1)
        if snippets:
            cis_guidance_list.extend(snippets)

    user_prompt = format_narrative_prompt(path, cis_guidance_list)

    api_key = Config.ANTHROPIC_API_KEY
    if api_key:
        try:
            from langchain_anthropic import ChatAnthropic
            llm = ChatAnthropic(model_name="claude-3-5-sonnet-20241022", anthropic_api_key=api_key)
            messages = [
                ("system", NARRATIVE_SYSTEM_PROMPT),
                ("user", user_prompt)
            ]
            response = llm.invoke(messages)
            return str(response.content).strip()
        except Exception as e:
            logger.warning(f"LLM API call failed ({e}), falling back to deterministic narrative generator.")

    return generate_fallback_narrative(path, cis_guidance_list)
