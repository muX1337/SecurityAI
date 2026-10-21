from openredirect_ai.context import ContextSpec
from openredirect_ai.filter_harness import generate_pairs, load_contexts


def test_load_contexts_from_yaml(tmp_path):
    yaml_text = """
contexts:
  - id: t1
    location: redirect_param
    filters: []
"""
    f = tmp_path / "contexts.yaml"
    f.write_text(yaml_text)
    ctxs = load_contexts(f)
    assert len(ctxs) == 1
    assert ctxs[0].id == "t1"
    assert ctxs[0].location == "redirect_param"


def test_generate_pairs_keeps_firing_urls():
    payloads = [
        "https://evil.com/",   # fires
        "/home",               # does not fire (relative)
        "test_input",          # does not fire
    ]
    ctx = ContextSpec(id="redirect-param-plain", location="redirect_param", filters=[])
    pairs = generate_pairs([ctx], payloads, per_context_cap=100)
    assert len(pairs) == 1
    assert pairs[0].payload == "https://evil.com/"


def test_generate_pairs_block_absolute_keeps_protocol_relative():
    payloads = [
        "https://evil.com/",  # blocked by filter
        "//evil.com/",        # survives, fires
    ]
    ctx = ContextSpec(id="redirect-param-block-absolute", location="redirect_param",
                      filters=["block_absolute_url"])
    pairs = generate_pairs([ctx], payloads, per_context_cap=100)
    assert len(pairs) == 1
    assert pairs[0].payload == "//evil.com/"


def test_generate_pairs_caps_per_context():
    payloads = [f"https://example{i}.com/" for i in range(50)]
    ctx = ContextSpec(id="c", location="redirect_param", filters=[])
    pairs = generate_pairs([ctx], payloads, per_context_cap=10)
    assert len(pairs) == 10


def test_generate_pairs_dedups_normalized():
    # same payload twice -> one pair
    payloads = ["https://evil.com/", "HTTPS://Evil.com/  "]
    ctx = ContextSpec(id="c", location="redirect_param", filters=[])
    pairs = generate_pairs([ctx], payloads, per_context_cap=100)
    assert len(pairs) == 1


def test_pair_provenance_is_filter_harness():
    ctx = ContextSpec(id="c", location="redirect_param", filters=[])
    pairs = generate_pairs([ctx], ["https://evil.com/"], per_context_cap=10)
    assert pairs[0].provenance["source"] == "filter_harness"
    assert pairs[0].provenance["verified_by"] == "filter_sim"


def test_pair_has_description_and_id():
    ctx = ContextSpec(id="redirect-param-plain", location="redirect_param", filters=[])
    pairs = generate_pairs([ctx], ["https://evil.com/"], per_context_cap=10)
    assert pairs[0].context.description
    assert pairs[0].id


def test_load_full_taxonomy(repo_root):
    """The committed openredirect_contexts.yaml loads with >= 20 contexts."""
    path = repo_root / "data" / "contexts" / "openredirect_contexts.yaml"
    ctxs = load_contexts(path)
    assert len(ctxs) >= 20
    ids = {c.id for c in ctxs}
    assert "redirect-param-plain" in ids
