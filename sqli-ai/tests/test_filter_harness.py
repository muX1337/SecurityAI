"""Tests for filter_harness.py: load_contexts, generate_pairs, write_pairs_jsonl."""
from __future__ import annotations

import json

from sqli_ai.context import ContextSpec, render_description
from sqli_ai.filter_harness import (
    _pair_id,
    generate_pairs,
    load_contexts,
    write_pairs_jsonl,
)


class TestLoadContexts:
    def test_loads_from_yaml(self, tmp_path):
        yaml_text = """
contexts:
  - id: t1
    location: string_literal
    filters: []
  - id: t2
    location: numeric
    filters: [block_keyword_union]
"""
        f = tmp_path / "contexts.yaml"
        f.write_text(yaml_text)
        ctxs = load_contexts(f)
        assert len(ctxs) == 2
        assert ctxs[0].id == "t1"
        assert ctxs[0].location == "string_literal"
        assert ctxs[1].filters == ["block_keyword_union"]

    def test_sets_rendered_description(self, tmp_path):
        yaml_text = """
contexts:
  - id: t1
    location: numeric
"""
        f = tmp_path / "contexts.yaml"
        f.write_text(yaml_text)
        ctxs = load_contexts(f)
        assert ctxs[0].description is not None
        assert "numeric" in ctxs[0].description.lower()

    def test_real_contexts_file(self, repo_root):
        path = repo_root / "data" / "contexts" / "sqli_contexts.yaml"
        ctxs = load_contexts(path)
        assert len(ctxs) >= 20  # expanded in v2
        for ctx in ctxs:
            assert ctx.id
            assert ctx.description is not None


class TestGeneratePairs:
    def test_keeps_passing_payloads(self):
        payloads = [
            "' OR 1=1 --",
            "1 UNION SELECT 1,2,3 --",
            "not sqli at all",
        ]
        ctx = ContextSpec(id="sqli-string-plain", location="string_literal")
        pairs = generate_pairs([ctx], payloads, per_context_cap=100)
        payloads_out = {p.payload for p in pairs}
        assert "' OR 1=1 --" in payloads_out
        assert "1 UNION SELECT 1,2,3 --" in payloads_out
        assert "not sqli at all" not in payloads_out

    def test_blocks_dropped(self):
        payloads = ["1 UNION SELECT 1,2,3 --", "1 OR 1=1"]
        ctx = ContextSpec(
            id="sqli-numeric-block-union", location="numeric",
            filters=["block_keyword_union"],
        )
        pairs = generate_pairs([ctx], payloads, per_context_cap=100)
        payloads_out = {p.payload for p in pairs}
        assert "1 UNION SELECT 1,2,3 --" not in payloads_out  # blocked
        assert "1 OR 1=1" in payloads_out

    def test_per_context_cap(self):
        payloads = [f"' OR {i}={i} --" for i in range(50)]
        ctx = ContextSpec(id="c", location="string_literal")
        pairs = generate_pairs([ctx], payloads, per_context_cap=10)
        assert len(pairs) == 10

    def test_dedups_normalized_payloads_per_context(self):
        # Same payload text (whitespace differs after normalize) -> kept once.
        payloads = ["' OR 1=1 --", "'  OR  1=1  --"]
        ctx = ContextSpec(id="c", location="string_literal")
        pairs = generate_pairs([ctx], payloads, per_context_cap=100)
        assert len(pairs) == 1

    def test_provenance_is_filter_harness(self):
        ctx = ContextSpec(id="c", location="string_literal")
        pairs = generate_pairs([ctx], ["' OR 1=1 --"], per_context_cap=10)
        assert pairs[0].provenance["source"] == "filter_harness"
        assert pairs[0].provenance["verified_by"] == "filter_sim"

    def test_pair_has_description_and_id(self):
        ctx = ContextSpec(id="sqli-string-plain", location="string_literal")
        pairs = generate_pairs([ctx], ["' OR 1=1 --"], per_context_cap=10)
        assert pairs[0].context.description
        assert pairs[0].id

    def test_pair_id_includes_context_and_hash(self):
        ctx = ContextSpec(id="sqli-string-plain", location="string_literal")
        pid = _pair_id(ctx, "' OR 1=1 --")
        assert pid.startswith("sqli-string-plain__pl-")
        assert len(pid) > len("sqli-string-plain__pl-")

    def test_numeric_payload_only_in_numeric_context(self):
        # "999" can_fire only in numeric context.
        ctx_str = ContextSpec(id="c-str", location="string_literal")
        ctx_num = ContextSpec(id="c-num", location="numeric")
        pairs = generate_pairs([ctx_str, ctx_num], ["999"], per_context_cap=100)
        ctx_ids = {p.context.id for p in pairs}
        assert "c-num" in ctx_ids
        assert "c-str" not in ctx_ids

    def test_results_deterministic_for_seed(self):
        ctx = ContextSpec(id="c", location="string_literal")
        payloads = [f"' OR {i}={i} --" for i in range(20)]
        a = generate_pairs([ctx], payloads, per_context_cap=10, seed=0)
        b = generate_pairs([ctx], payloads, per_context_cap=10, seed=0)
        assert [p.id for p in a] == [p.id for p in b]


class TestWritePairsJsonl:
    def test_writes_one_json_per_line(self, tmp_path):
        ctx = ContextSpec(id="c", location="string_literal")
        ctx.description = render_description(ctx)
        from sqli_ai.pair_schema import Pair, Provenance

        pairs = [
            Pair(
                id="c__pl-abc12345",
                context=ctx,
                payload="' OR 1=1 --",
                provenance=Provenance(source="filter_harness", verified_by="filter_sim"),
            )
        ]
        out = tmp_path / "pairs.jsonl"
        write_pairs_jsonl(pairs, out)
        lines = out.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        rec = json.loads(lines[0])
        assert rec["payload"] == "' OR 1=1 --"
        assert rec["id"] == "c__pl-abc12345"

    def test_creates_parent_dir(self, tmp_path):
        ctx = ContextSpec(id="c", location="string_literal")
        pairs = generate_pairs([ctx], ["' OR 1=1 --"], per_context_cap=10)
        out = tmp_path / "nested" / "deep" / "pairs.jsonl"
        write_pairs_jsonl(pairs, out)
        assert out.exists()
