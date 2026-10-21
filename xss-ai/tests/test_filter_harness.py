from xss_ai.context import ContextSpec
from xss_ai.filter_harness import generate_pairs, load_contexts


def test_load_contexts_from_yaml(tmp_path):
    yaml_text = """
contexts:
  - id: t1
    location: html_body
    filters: []
"""
    f = tmp_path / "contexts.yaml"
    f.write_text(yaml_text)
    ctxs = load_contexts(f)
    assert len(ctxs) == 1
    assert ctxs[0].id == "t1"
    assert ctxs[0].location == "html_body"

def test_generate_pairs_keeps_only_firing(tmp_path):
    payloads = [
        "<script>alert(1)</script>",      # fires in body, no filter
        "hello world",                      # does not fire
        "<svg onload=alert(1)>",           # fires
    ]
    ctx = ContextSpec(id="html-body-plain", location="html_body", filters=[])
    pairs = generate_pairs([ctx], payloads, per_context_cap=100)
    assert len(pairs) == 2
    payloads_out = {p.payload for p in pairs}
    assert "<script>alert(1)</script>" in payloads_out
    assert "hello world" not in payloads_out

def test_generate_pairs_respects_filter(tmp_path):
    # block_keyword_script: <script> payload gets emptied -> dropped
    payloads = ["<script>alert(1)</script>", "<svg onload=alert(1)>"]
    ctx = ContextSpec(id="html-body-block-script", location="html_body",
                      filters=["block_keyword_script"])
    pairs = generate_pairs([ctx], payloads, per_context_cap=100)
    assert len(pairs) == 1
    assert pairs[0].payload == "<svg onload=alert(1)>"

def test_generate_pairs_caps_per_context():
    payloads = [f"<svg onload=alert({i})>" for i in range(50)]
    ctx = ContextSpec(id="c", location="html_body", filters=[])
    pairs = generate_pairs([ctx], payloads, per_context_cap=10)
    assert len(pairs) == 10

def test_pair_provenance_source_is_filter_harness():
    ctx = ContextSpec(id="c", location="html_body", filters=[])
    pairs = generate_pairs([ctx], ["<script>alert(1)</script>"], per_context_cap=10)
    assert pairs[0].provenance["source"] == "filter_harness"
    assert pairs[0].provenance["verified_by"] == "filter_sim"

def test_pair_has_description_and_id():
    ctx = ContextSpec(id="html-body-plain", location="html_body", filters=[])
    pairs = generate_pairs([ctx], ["<script>alert(1)</script>"], per_context_cap=10)
    assert pairs[0].context.description  # rendered, non-empty
    assert pairs[0].id  # non-empty
