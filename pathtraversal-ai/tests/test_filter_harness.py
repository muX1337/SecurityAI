"""Tests for filter_harness.py: load_contexts, generate_pairs, write_pairs_jsonl."""
from __future__ import annotations

import json

from pathtraversal_ai.context import ContextSpec, render_description
from pathtraversal_ai.filter_harness import (
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
    location: file_include
    filters: []
  - id: t2
    location: file_read
    filters: [strip_dotdot]
"""
        f = tmp_path / "contexts.yaml"
        f.write_text(yaml_text)
        ctxs = load_contexts(f)
        assert len(ctxs) == 2
        assert ctxs[0].id == "t1"
        assert ctxs[0].location == "file_include"
        assert ctxs[1].filters == ["strip_dotdot"]

    def test_sets_rendered_description(self, tmp_path):
        yaml_text = """
contexts:
  - id: t1
    location: file_read
"""
        f = tmp_path / "contexts.yaml"
        f.write_text(yaml_text)
        ctxs = load_contexts(f)
        assert ctxs[0].description is not None
        assert "read" in ctxs[0].description.lower() or "file_get_contents" in ctxs[0].description.lower()

    def test_real_contexts_file(self, repo_root):
        path = repo_root / "data" / "contexts" / "pathtraversal_contexts.yaml"
        ctxs = load_contexts(path)
        assert len(ctxs) >= 20
        for ctx in ctxs:
            assert ctx.id
            assert ctx.description is not None


class TestGeneratePairs:
    def test_keeps_passing_payloads(self):
        payloads = [
            "../../../etc/passwd",
            "/etc/shadow",
            "safe_file.txt",
        ]
        ctx = ContextSpec(id="lfi-fileread-plain", location="file_read")
        pairs = generate_pairs([ctx], payloads, per_context_cap=100)
        payloads_out = {p.payload for p in pairs}
        assert "../../../etc/passwd" in payloads_out
        assert "/etc/shadow" in payloads_out
        assert "safe_file.txt" not in payloads_out

    def test_blocks_dropped(self):
        payloads = ["/etc/passwd", "../../../etc/passwd"]
        ctx = ContextSpec(
            id="lfi-fileread-block-absolute", location="file_read",
            filters=["block_absolute"],
        )
        pairs = generate_pairs([ctx], payloads, per_context_cap=100)
        payloads_out = {p.payload for p in pairs}
        assert "/etc/passwd" not in payloads_out  # blocked
        assert "../../../etc/passwd" in payloads_out

    def test_per_context_cap(self):
        payloads = [f"../../../etc/{i}" for i in range(50)]
        ctx = ContextSpec(id="c", location="file_read")
        pairs = generate_pairs([ctx], payloads, per_context_cap=10)
        assert len(pairs) == 10

    def test_dedups_normalized_payloads_per_context(self):
        payloads = ["../../../etc/passwd", "../../../etc/passwd"]
        ctx = ContextSpec(id="c", location="file_read")
        pairs = generate_pairs([ctx], payloads, per_context_cap=100)
        assert len(pairs) == 1

    def test_provenance_is_filter_harness(self):
        ctx = ContextSpec(id="c", location="file_read")
        pairs = generate_pairs([ctx], ["../../../etc/passwd"], per_context_cap=10)
        assert pairs[0].provenance["source"] == "filter_harness"
        assert pairs[0].provenance["verified_by"] == "filter_sim"

    def test_pair_has_description_and_id(self):
        ctx = ContextSpec(id="lfi-fileread-plain", location="file_read")
        pairs = generate_pairs([ctx], ["../../../etc/passwd"], per_context_cap=10)
        assert pairs[0].context.description
        assert pairs[0].id

    def test_pair_id_includes_context_and_hash(self):
        ctx = ContextSpec(id="lfi-fileread-plain", location="file_read")
        pid = _pair_id(ctx, "../../../etc/passwd")
        assert pid.startswith("lfi-fileread-plain__pl-")
        assert len(pid) > len("lfi-fileread-plain__pl-")

    def test_results_deterministic_for_seed(self):
        ctx = ContextSpec(id="c", location="file_read")
        payloads = [f"../../../etc/{i}" for i in range(20)]
        a = generate_pairs([ctx], payloads, per_context_cap=10, seed=0)
        b = generate_pairs([ctx], payloads, per_context_cap=10, seed=0)
        assert [p.id for p in a] == [p.id for p in b]


class TestWritePairsJsonl:
    def test_writes_one_json_per_line(self, tmp_path):
        ctx = ContextSpec(id="c", location="file_read")
        ctx.description = render_description(ctx)
        from pathtraversal_ai.pair_schema import Pair, Provenance

        pairs = [
            Pair(
                id="c__pl-abc12345",
                context=ctx,
                payload="../../../etc/passwd",
                provenance=Provenance(source="filter_harness", verified_by="filter_sim"),
            )
        ]
        out = tmp_path / "pairs.jsonl"
        write_pairs_jsonl(pairs, out)
        lines = out.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        rec = json.loads(lines[0])
        assert rec["payload"] == "../../../etc/passwd"
        assert rec["id"] == "c__pl-abc12345"

    def test_creates_parent_dir(self, tmp_path):
        ctx = ContextSpec(id="c", location="file_read")
        pairs = generate_pairs([ctx], ["../../../etc/passwd"], per_context_cap=10)
        out = tmp_path / "nested" / "deep" / "pairs.jsonl"
        write_pairs_jsonl(pairs, out)
        assert out.exists()
