"""Prompt formatting for XXE payload generation training and inference.

Training text format:
    ### Context:
    {context description}

    ### Payload:
    {payload}

Loss is computed only on the payload portion (after ### Payload:\\n).
"""
from __future__ import annotations

PROMPT_PREFIX = "### Context:\n"
PROMPT_SEPARATOR = "\n\n### Payload:\n"
EOS_MARKER = "<|im_end|>"  # Qwen2.5 chat template end token; used as stop signal


def format_prompt(description: str) -> str:
    """Format a context description into the prompt portion (no payload)."""
    return f"{PROMPT_PREFIX}{description}{PROMPT_SEPARATOR}"


def format_example(description: str, payload: str) -> str:
    """Format a complete (description, payload) pair into training text."""
    return f"{PROMPT_PREFIX}{description}{PROMPT_SEPARATOR}{payload}"


def extract_payload(generated_text: str) -> str | None:
    """Extract the payload from generated text by finding the ### Payload: marker.

    Returns None if the marker is absent. Strips leading whitespace and
    truncates at the first newline after the payload (model may generate
    trailing junk).
    """
    marker_idx = generated_text.rfind(PROMPT_SEPARATOR)
    if marker_idx == -1:
        return None
    after_marker = generated_text[marker_idx + len(PROMPT_SEPARATOR):]
    # Skip the leading newline that follows ### Payload:
    after_marker = after_marker.lstrip("\n")
    # Truncate at first newline (payloads don't contain newlines)
    payload = after_marker.split("\n")[0]
    return payload if payload else None
