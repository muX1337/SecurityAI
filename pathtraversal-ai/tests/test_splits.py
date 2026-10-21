"""Tests for splits.py: stratified split, leakage, quality gates."""
from __future__ import annotations

from pathtraversal_ai.context import ContextSpec
from pathtraversal_ai.pair_schema import Pair, Provenance
from pathtraversal_ai.splits import (
    check_leakage,
    normalize_for_dedup,
    run_quality_gates,
    stratified_split,
)


def _make_pair(ctx_id: str, payload: str, location: str = "file_read") -> Pair:
    ctx = ContextSpec(id=ctx_id, location=location)
    ctx.description = f"desc for {ctx_id}"
    return Pair(
        id=f"{ctx_id}__pl-{abs(hash(payload)) % 100000000:08d}",
        context=ctx,
        payload=payload,
        provenance=Provenance(source="filter_harness", verified_by="filter_sim"),
    )


class TestNormalizeForDedup:
    def test_lowercases(self):
        assert normalize_for_dedup("../ETC/passwd") == "../etc/passwd"

    def test_strips_whitespace(self):
        assert normalize_for_dedup("  ../ etc /passwd  ") == "../etc/passwd"

    def test_strips_all_whitespace(self):
        assert normalize_for_dedup("../ e t c") == "../etc"


class TestStratifiedSplit:
    def test_all_payloads_assigned(self):
        pairs = [_make_pair("c", f"../../../etc/{i}") for i in range(100)]
        splits = stratified_split(pairs, seed=0)
        total = len(splits["train"]) + len(splits["val"]) + len(splits["test"])
        assert total == 100

    def test_no_leakage_by_construction(self):
        pairs = [_make_pair("c", f"../../../etc/{i}") for i in range(100)]
        splits = stratified_split(pairs, seed=0)
        leaked = check_leakage(splits["train"], splits["test"])
        assert leaked == []

    def test_split_ratios_roughly_correct(self):
        pairs = [_make_pair("c", f"../../../etc/{i}") for i in range(1000)]
        splits = stratified_split(pairs, seed=0)
        assert len(splits["train"]) > 700  # ~80%
        assert len(splits["val"]) < 200    # ~10%
        assert len(splits["test"]) < 200   # ~10%

    def test_same_payload_in_different_splits_together(self):
        pairs = [_make_pair("c1", "../../../etc/passwd"), _make_pair("c2", "../../../etc/passwd")]
        splits = stratified_split(pairs, seed=0)
        for split in ("train", "val", "test"):
            ids = {p.context.id for p in splits[split]}
            if "c1" in ids:
                assert "c2" in ids


class TestCheckLeakage:
    def test_no_leakage(self):
        train = [_make_pair("c", "../../../etc/a")]
        test = [_make_pair("c", "../../../etc/b")]
        assert check_leakage(train, test) == []

    def test_detects_leakage(self):
        train = [_make_pair("c", "../../../etc/passwd")]
        test = [_make_pair("c", "../../../etc/passwd")]
        leaked = check_leakage(train, test)
        assert normalize_for_dedup("../../../etc/passwd") in leaked


class TestRunQualityGates:
    def test_passes_with_enough_data(self):
        ctxs = [f"c{i}" for i in range(15)]
        pairs = []
        for ctx_id in ctxs:
            for j in range(50):
                pairs.append(_make_pair(ctx_id, f"../../../etc/{ctx_id}_{j}"))
        gates = run_quality_gates(pairs, [])
        assert gates["passed"] is True
        assert gates["violations"] == []

    def test_fails_on_too_few_pairs(self):
        pairs = [_make_pair("c", f"../../../etc/{i}") for i in range(10)]
        gates = run_quality_gates(pairs, [], min_train_pairs=500)
        assert gates["passed"] is False

    def test_fails_on_too_few_contexts(self):
        pairs = [_make_pair("c", f"../../../etc/{i}") for i in range(600)]
        gates = run_quality_gates(pairs, [], min_contexts=10)
        assert gates["passed"] is False

    def test_fails_on_context_imbalance(self):
        pairs = [_make_pair("big", f"../../../etc/{i}") for i in range(500)]
        pairs += [_make_pair("c1", "../../../etc/1")]
        gates = run_quality_gates(pairs, [])
        assert gates["passed"] is False

    def test_stats_include_context_counts(self):
        pairs = [_make_pair("c1", "../../../etc/1"), _make_pair("c2", "../../../etc/2")]
        gates = run_quality_gates(pairs, [], min_train_pairs=1, min_contexts=1)
        assert "context_counts" in gates["stats"]
