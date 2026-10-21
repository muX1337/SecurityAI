"""Tests for filter_harness.py: load_contexts, generate_pairs, write_pairs_jsonl."""
from __future__ import annotations

import json

from cmdi_ai.context import ContextSpec, render_description
from cmdi_ai.filter_harness import (
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
    location: shell_arg
    filters: []
  - id: t2
    location: shell_command
    filters: [block_semicolon]
"""
        f = tmp_path / "contexts.yaml"
        f.write_text(yaml_text)
        ctxs = load_contexts(f)
        assert len(ctxs) == 2
        assert ctxs[0].id == "t1"
        assert ctxs[0].location == "shell_arg"
        assert ctxs[1].filters == ["block_semicolon"]

    def test_sets_rendered_description(self, tmp_path):
        yaml_text = """
contexts:
  - id: t1
    location: shell_command
"""
        f = tmp_path / "contexts.yaml"
        f.write_text(yaml_text)
        ctxs = load_contexts(f)
        assert ctxs[0].description is not None
        assert "command" in ctxs[0].description.lower()

    def test_real_contexts_file(self, repo_root):
        path = repo_root / "data" / "contexts" / "cmdi_contexts.yaml"
        ctxs = load_contexts(path)
        assert len(ctxs) >= 20
        for ctx in ctxs:
            assert ctx.id
            assert ctx.description is not None


class TestGeneratePairs:
    def test_keeps_passing_payloads(self):
        payloads = [
            ";whoami",
            "|whoami",
            "not injection at all",
        ]
        ctx = ContextSpec(id="cmdi-shellarg-plain", location="shell_arg")
        pairs = generate_pairs([ctx], payloads, per_context_cap=100)
        payloads_out = {p.payload for p in pairs}
        assert ";whoami" in payloads_out
        assert "|whoami" in payloads_out
        assert "not injection at all" not in payloads_out

    def test_blocks_dropped(self):
        payloads = [";whoami", "|whoami"]
        ctx = ContextSpec(
            id="cmdi-shellarg-block-semicolon", location="shell_arg",
            filters=["block_semicolon"],
        )
        pairs = generate_pairs([ctx], payloads, per_context_cap=100)
        payloads_out = {p.payload for p in pairs}
        assert ";whoami" not in payloads_out  # blocked
        assert "|whoami" in payloads_out

    def test_per_context_cap(self):
        payloads = [f";whoami{i}" for i in range(50)]
        ctx = ContextSpec(id="c", location="shell_arg")
        pairs = generate_pairs([ctx], payloads, per_context_cap=10)
        assert len(pairs) == 10

    def test_dedups_normalized_payloads_per_context(self):
        payloads = [";whoami", ";  whoami"]
        ctx = ContextSpec(id="c", location="shell_arg")
        pairs = generate_pairs([ctx], payloads, per_context_cap=100)
        assert len(pairs) == 1

    def test_provenance_is_filter_harness(self):
        ctx = ContextSpec(id="c", location="shell_arg")
        pairs = generate_pairs([ctx], [";whoami"], per_context_cap=10)
        assert pairs[0].provenance["source"] == "filter_harness"
        assert pairs[0].provenance["verified_by"] == "filter_sim"

    def test_pair_has_description_and_id(self):
        ctx = ContextSpec(id="cmdi-shellarg-plain", location="shell_arg")
        pairs = generate_pairs([ctx], [";whoami"], per_context_cap=10)
        assert pairs[0].context.description
        assert pairs[0].id

    def test_pair_id_includes_context_and_hash(self):
        ctx = ContextSpec(id="cmdi-shellarg-plain", location="shell_arg")
        pid = _pair_id(ctx, ";whoami")
        assert pid.startswith("cmdi-shellarg-plain__pl-")
        assert len(pid) > len("cmdi-shellarg-plain__pl-")

    def test_shell_command_keyword_only_in_command_context(self):
        # "whoami" can_fire only in shell_command context.
        ctx_arg = ContextSpec(id="c-arg", location="shell_arg")
        ctx_cmd = ContextSpec(id="c-cmd", location="shell_command")
        pairs = generate_pairs([ctx_arg, ctx_cmd], ["whoami"], per_context_cap=100)
        ctx_ids = {p.context.id for p in pairs}
        assert "c-cmd" in ctx_ids
        assert "c-arg" not in ctx_ids

    def test_results_deterministic_for_seed(self):
        ctx = ContextSpec(id="c", location="shell_arg")
        payloads = [f";whoami{i}" for i in range(20)]
        a = generate_pairs([ctx], payloads, per_context_cap=10, seed=0)
        b = generate_pairs([ctx], payloads, per_context_cap=10, seed=0)
        assert [p.id for p in a] == [p.id for p in b]


class TestWritePairsJsonl:
    def test_writes_one_json_per_line(self, tmp_path):
        ctx = ContextSpec(id="c", location="shell_arg")
        ctx.description = render_description(ctx)
        from cmdi_ai.pair_schema import Pair, Provenance

        pairs = [
            Pair(
                id="c__pl-abc12345",
                context=ctx,
                payload=";whoami",
                provenance=Provenance(source="filter_harness", verified_by="filter_sim"),
            )
        ]
        out = tmp_path / "pairs.jsonl"
        write_pairs_jsonl(pairs, out)
        lines = out.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        rec = json.loads(lines[0])
        assert rec["payload"] == ";whoami"
        assert rec["id"] == "c__pl-abc12345"

    def test_creates_parent_dir(self, tmp_path):
        ctx = ContextSpec(id="c", location="shell_arg")
        pairs = generate_pairs([ctx], [";whoami"], per_context_cap=10)
        out = tmp_path / "nested" / "deep" / "pairs.jsonl"
        write_pairs_jsonl(pairs, out)
        assert out.exists()
