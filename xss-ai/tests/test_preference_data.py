"""Tests for preference data formatting (DPO pair structure)."""
import json

from xss_ai.preference_data import format_for_dpo, load_preference_pairs


def test_format_for_dpo_basic():
    desc = "Input is reflected into the HTML body."
    chosen = "<svg onload=alert(1)>"
    rejected = "hello world"
    result = format_for_dpo(desc, chosen, rejected)
    assert result["prompt"].startswith("### Context:")
    assert desc in result["prompt"]
    assert result["prompt"].endswith("### Payload:\n")
    assert result["chosen"] == chosen
    assert result["rejected"] == rejected


def test_format_for_dpo_prompt_has_separator():
    result = format_for_dpo("desc", "chosen_payload", "rejected_payload")
    assert "### Payload:" in result["prompt"]


def test_load_preference_pairs(tmp_path):
    f = tmp_path / "prefs.jsonl"
    pairs = [
        format_for_dpo("desc1", "<svg onload=alert(1)>", "not a payload"),
        format_for_dpo("desc2", "<img onerror=alert(1)>", "hello"),
    ]
    lines = [json.dumps(p) for p in pairs]
    f.write_text("\n".join(lines) + "\n")

    loaded = load_preference_pairs(f)
    assert len(loaded) == 2
    assert loaded[0]["chosen"] == "<svg onload=alert(1)>"
    assert loaded[1]["rejected"] == "hello"


def test_load_preference_pairs_skips_empty_lines(tmp_path):
    f = tmp_path / "prefs.jsonl"
    p = format_for_dpo("d", "a", "b")
    f.write_text(json.dumps(p) + "\n\n\n")
    loaded = load_preference_pairs(f)
    assert len(loaded) == 1
