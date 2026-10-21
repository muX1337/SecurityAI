from xxe_ai.context import ContextSpec
from xxe_ai.filter_harness import generate_pairs, load_contexts


def test_load_contexts_from_yaml(tmp_path):
    yaml_text = """
contexts:
  - id: t1
    location: xml_body
    filters: []
"""
    f = tmp_path / "contexts.yaml"
    f.write_text(yaml_text)
    ctxs = load_contexts(f)
    assert len(ctxs) == 1
    assert ctxs[0].id == "t1"
    assert ctxs[0].location == "xml_body"

def test_generate_pairs_keeps_passing_payloads():
    payloads = [
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        "<root>plain</root>",
        "not xml",
    ]
    ctx = ContextSpec(id="xxe-body-plain", location="xml_body", filters=[])
    pairs = generate_pairs([ctx], payloads, per_context_cap=100)
    assert len(pairs) == 1
    assert "ENTITY" in pairs[0].payload

def test_generate_pairs_filters_block_doctype():
    payload = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    ctx = ContextSpec(id="xxe-body-block-doctype", location="xml_body",
                      filters=["block_doctype"])
    pairs = generate_pairs([ctx], [payload], per_context_cap=100)
    assert len(pairs) == 0  # blocked entirely

def test_generate_pairs_block_file_allows_http():
    file_pl = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    http_pl = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]><foo>&xxe;</foo>'
    ctx = ContextSpec(id="xxe-body-block-file", location="xml_body",
                      filters=["block_file_protocol"])
    pairs = generate_pairs([ctx], [file_pl, http_pl], per_context_cap=100)
    assert len(pairs) == 1
    assert "http://" in pairs[0].payload

def test_generate_pairs_caps_per_context():
    payloads = [
        f'<!DOCTYPE foo [<!ENTITY x{i} SYSTEM "file:///etc/passwd">]><foo>&x{i};</foo>'
        for i in range(50)
    ]
    ctx = ContextSpec(id="c", location="xml_body", filters=[])
    pairs = generate_pairs([ctx], payloads, per_context_cap=10)
    assert len(pairs) == 10

def test_pair_provenance_is_filter_harness():
    ctx = ContextSpec(id="c", location="xml_body", filters=[])
    payload = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    pairs = generate_pairs([ctx], [payload], per_context_cap=10)
    assert pairs[0].provenance["source"] == "filter_harness"
    assert pairs[0].provenance["verified_by"] == "filter_sim"

def test_pair_has_description_and_id():
    ctx = ContextSpec(id="xxe-body-plain", location="xml_body", filters=[])
    payload = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    pairs = generate_pairs([ctx], [payload], per_context_cap=10)
    assert pairs[0].context.description
    assert pairs[0].id
