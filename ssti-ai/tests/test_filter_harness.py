from ssti_ai.context import ContextSpec
from ssti_ai.filter_harness import generate_pairs, load_contexts


def test_load_contexts_from_yaml(tmp_path):
    yaml_text = """
contexts:
  - id: t1
    location: jinja2_body
    filters: []
"""
    f = tmp_path / "contexts.yaml"
    f.write_text(yaml_text)
    ctxs = load_contexts(f)
    assert len(ctxs) == 1
    assert ctxs[0].id == "t1"
    assert ctxs[0].location == "jinja2_body"

def test_generate_pairs_keeps_passing_payloads():
    payloads = [
        "{{7*7}}",
        "{{config}}",
        "not a template",
    ]
    ctx = ContextSpec(id="ssti-jinja2-plain", location="jinja2_body", filters=[])
    pairs = generate_pairs([ctx], payloads, per_context_cap=100)
    payloads_out = {p.payload for p in pairs}
    assert "{{7*7}}" in payloads_out
    assert "{{config}}" in payloads_out
    assert "not a template" not in payloads_out

def test_generate_pairs_filter_blocks_curly():
    payloads = ["{{7*7}}", "${7*7}"]
    ctx = ContextSpec(id="ssti-jinja2-block-curly", location="jinja2_body",
                      filters=["block_curly_braces"])
    pairs = generate_pairs([ctx], payloads, per_context_cap=100)
    # {{7*7}} is blocked; ${7*7} doesn't fire on jinja2 either -> 0 pairs
    assert len(pairs) == 0

def test_generate_pairs_caps_per_context():
    payloads = [f"{{{{7*{i}}}}}" for i in range(50)]
    ctx = ContextSpec(id="c", location="jinja2_body", filters=[])
    pairs = generate_pairs([ctx], payloads, per_context_cap=10)
    assert len(pairs) == 10

def test_pair_provenance_is_filter_harness():
    ctx = ContextSpec(id="c", location="jinja2_body", filters=[])
    pairs = generate_pairs([ctx], ["{{7*7}}"], per_context_cap=10)
    assert pairs[0].provenance["source"] == "filter_harness"
    assert pairs[0].provenance["verified_by"] == "filter_sim"

def test_pair_has_description_and_id():
    ctx = ContextSpec(id="ssti-jinja2-plain", location="jinja2_body", filters=[])
    pairs = generate_pairs([ctx], ["{{7*7}}"], per_context_cap=10)
    assert pairs[0].context.description
    assert pairs[0].id

def test_generate_pairs_freemarker_dollar():
    payloads = ["${7*7}", "{{7*7}}"]
    ctx = ContextSpec(id="c", location="freemarker_body", filters=[])
    pairs = generate_pairs([ctx], payloads, per_context_cap=100)
    payloads_out = {p.payload for p in pairs}
    assert "${7*7}" in payloads_out
    # {{7*7}} does not fire on freemarker (no curly delimiters) -> excluded
    assert "{{7*7}}" not in payloads_out
