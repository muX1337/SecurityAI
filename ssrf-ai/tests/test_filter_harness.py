from ssrf_ai.context import ContextSpec
from ssrf_ai.filter_harness import generate_pairs, load_contexts


def test_load_contexts_from_yaml(tmp_path):
    yaml_text = """
contexts:
  - id: t1
    location: query_param
    filters: []
"""
    f = tmp_path / "contexts.yaml"
    f.write_text(yaml_text)
    ctxs = load_contexts(f)
    assert len(ctxs) == 1
    assert ctxs[0].id == "t1"
    assert ctxs[0].location == "query_param"

def test_generate_pairs_keeps_passing_urls():
    payloads = [
        "http://8.8.8.8/",
        "http://127.0.0.1/",
        "not a url",
    ]
    ctx = ContextSpec(id="ssrf-query-block-private-ip", location="query_param",
                      filters=["block_private_ip"])
    pairs = generate_pairs([ctx], payloads, per_context_cap=100)
    assert len(pairs) == 1
    assert pairs[0].payload == "http://8.8.8.8/"

def test_generate_pairs_no_filter_keeps_internal():
    payloads = ["http://127.0.0.1/", "http://8.8.8.8/"]
    ctx = ContextSpec(id="ssrf-query-plain", location="query_param", filters=[])
    pairs = generate_pairs([ctx], payloads, per_context_cap=100)
    assert len(pairs) == 2

def test_generate_pairs_caps_per_context():
    payloads = [f"http://example{i}.com/" for i in range(50)]
    ctx = ContextSpec(id="c", location="query_param", filters=[])
    pairs = generate_pairs([ctx], payloads, per_context_cap=10)
    assert len(pairs) == 10

def test_pair_provenance_is_filter_harness():
    ctx = ContextSpec(id="c", location="query_param", filters=[])
    pairs = generate_pairs([ctx], ["http://example.com/"], per_context_cap=10)
    assert pairs[0].provenance["source"] == "filter_harness"
    assert pairs[0].provenance["verified_by"] == "filter_sim"

def test_pair_has_description_and_id():
    ctx = ContextSpec(id="ssrf-query-plain", location="query_param", filters=[])
    pairs = generate_pairs([ctx], ["http://example.com/"], per_context_cap=10)
    assert pairs[0].context.description
    assert pairs[0].id
