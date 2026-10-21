from crlf_ai.context import ContextSpec
from crlf_ai.filter_harness import generate_pairs, load_contexts, write_pairs_jsonl


def test_load_contexts_from_yaml(tmp_path):
    yaml_text = """
contexts:
  - id: t1
    location: response_header
    filters: []
"""
    f = tmp_path / "contexts.yaml"
    f.write_text(yaml_text)
    ctxs = load_contexts(f)
    assert len(ctxs) == 1
    assert ctxs[0].id == "t1"
    assert ctxs[0].location == "response_header"
    assert ctxs[0].description is not None  # render_description filled it


def test_load_contexts_renders_description(tmp_path):
    yaml_text = """
contexts:
  - id: t1
    location: set_cookie
    filters: [block_crlf]
"""
    f = tmp_path / "contexts.yaml"
    f.write_text(yaml_text)
    ctxs = load_contexts(f)
    desc = ctxs[0].description.lower()
    assert "set-cookie" in desc
    assert "crlf" in desc or "carriage" in desc


def test_generate_pairs_keeps_only_firing_payloads():
    payloads = [
        "%0d%0aSet-Cookie: evil=1",   # fires (plain context)
        "normal_value",                 # benign, does not fire
    ]
    ctx = ContextSpec(id="crlf-resp-header-plain", location="response_header", filters=[])
    pairs = generate_pairs([ctx], payloads, per_context_cap=100)
    assert len(pairs) == 1
    assert pairs[0].payload == "%0d%0aSet-Cookie: evil=1"


def test_generate_pairs_block_crlf_filters_out_literal():
    # Literal \r\n is blocked by block_crlf, so it must not survive.
    payloads = ["\r\nSet-Cookie: evil=1", "%0d%0aSet-Cookie: evil=1"]
    ctx = ContextSpec(id="crlf-resp-header-block-crlf",
                      location="response_header", filters=["block_crlf"])
    pairs = generate_pairs([ctx], payloads, per_context_cap=100)
    payloads_kept = {p.payload for p in pairs}
    assert "\r\nSet-Cookie: evil=1" not in payloads_kept


def test_generate_pairs_dedups_within_context():
    # Same normalized payload twice -> only one pair.
    payloads = ["%0d%0aSet-Cookie: evil=1", "%0D%0ASet-Cookie: evil=1"]
    ctx = ContextSpec(id="crlf-resp-header-plain", location="response_header", filters=[])
    pairs = generate_pairs([ctx], payloads, per_context_cap=100)
    assert len(pairs) == 1


def test_generate_pairs_caps_per_context():
    payloads = [f"%0d%0aSet-Cookie: evil={i}" for i in range(50)]
    ctx = ContextSpec(id="c", location="response_header", filters=[])
    pairs = generate_pairs([ctx], payloads, per_context_cap=10)
    assert len(pairs) == 10


def test_generate_pairs_assigns_unique_ids():
    payloads = ["%0d%0aSet-Cookie: a=1", "%0d%0aSet-Cookie: b=2"]
    ctx = ContextSpec(id="ctxA", location="response_header", filters=[])
    pairs = generate_pairs([ctx], payloads, per_context_cap=100)
    ids = [p.id for p in pairs]
    assert len(ids) == len(set(ids))
    assert all(i.startswith("ctxA__pl-") for i in ids)


def test_pair_provenance_is_filter_harness():
    ctx = ContextSpec(id="c", location="response_header", filters=[])
    pairs = generate_pairs([ctx], ["%0d%0aSet-Cookie: evil=1"], per_context_cap=10)
    assert pairs[0].provenance["source"] == "filter_harness"
    assert pairs[0].provenance["verified_by"] == "filter_sim"


def test_pair_has_description_and_id():
    ctx = ContextSpec(id="crlf-resp-header-plain", location="response_header", filters=[])
    pairs = generate_pairs([ctx], ["%0d%0aSet-Cookie: evil=1"], per_context_cap=10)
    assert pairs[0].context.description
    assert pairs[0].id


def test_write_pairs_jsonl_roundtrip(tmp_path):
    ctx = ContextSpec(id="crlf-resp-header-plain", location="response_header", filters=[])
    pairs = generate_pairs([ctx], ["%0d%0aSet-Cookie: evil=1"], per_context_cap=10)
    out = tmp_path / "pairs.jsonl"
    write_pairs_jsonl(pairs, out)
    assert out.exists()
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    assert "Set-Cookie" in lines[0]
