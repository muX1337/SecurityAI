from xss_ai.context import ContextSpec
from xss_ai.pair_schema import Pair, Provenance
from xss_ai.splits import (
    SPLIT_RATIOS,
    check_leakage,
    normalize_for_dedup,
    run_quality_gates,
    stratified_split,
)


def _pair(ctx_id, loc, payload):
    ctx = ContextSpec(id=ctx_id, location=loc)
    ctx.description = "d"
    return Pair(id=f"{ctx_id}-{payload}", context=ctx, payload=payload,
                provenance=Provenance(source="filter_harness", verified_by="filter_sim"))


def test_normalize_lowercases_and_strips():
    assert normalize_for_dedup("  <ScRiPt>  ") == "<script>"

def test_split_ratios_sum_to_one():
    assert abs(sum(SPLIT_RATIOS.values()) - 1.0) < 1e-9

def test_stratified_split_sizes():
    pairs = []
    for i in range(100):
        pairs.append(_pair("c1", "html_body", f"<svg onload=alert({i})>"))
    for i in range(100):
        pairs.append(_pair("c2", "attr_dq", f'x"><svg onload=alert({i})>'))
    splits = stratified_split(pairs, seed=0)
    total = sum(len(v) for v in splits.values())
    assert total == 200
    assert 0.78 < len(splits["train"]) / 200 < 0.82
    assert 0.08 < len(splits["val"]) / 200 < 0.12

def test_stratified_split_no_overlap():
    pairs = [_pair("c1", "html_body", f"p{i}") for i in range(50)]
    splits = stratified_split(pairs, seed=0)
    ids_train = {p.id for p in splits["train"]}
    ids_test = {p.id for p in splits["test"]}
    assert not (ids_train & ids_test)

def test_check_leakage_detects_overlap():
    train = [_pair("c1", "html_body", "<script>alert(1)</script>")]
    test = [_pair("c1", "html_body", "<script>alert(1)</script>")]
    leaked = check_leakage(train, test)
    assert len(leaked) >= 1

def test_check_leakage_clean():
    train = [_pair("c1", "html_body", "<script>alert(1)</script>")]
    test = [_pair("c1", "html_body", "<svg onload=alert(2)>")]
    assert check_leakage(train, test) == []

def test_quality_gates_pass_on_clean_split():
    pairs = []
    # 40 distinct contexts, each with enough payloads
    for ci in range(40):
        for i in range(20):
            pairs.append(_pair(f"ctx{ci}", "html_body", f"<svg onload=alert({ci}_{i})>"))
    splits = stratified_split(pairs, seed=0)
    # Tuned thresholds for this small synthetic fixture; production uses the
    # spec defaults (min_train_pairs=10_000, min_contexts=30).
    report = run_quality_gates(
        splits["train"], splits["test"], min_train_pairs=100, min_contexts=10
    )
    assert report["passed"] is True, report["violations"]

def test_quality_gates_fail_on_imbalance():
    # one context dominates (>8%)
    pairs = [_pair("big", "html_body", f"p{i}") for i in range(500)]
    for ci in range(5):
        for i in range(5):
            pairs.append(_pair(f"c{ci}", "html_body", f"q{ci}_{i}"))
    splits = stratified_split(pairs, seed=0)
    report = run_quality_gates(splits["train"], splits["test"])
    assert report["passed"] is False
    assert any("balance" in v for v in report["violations"])


def test_stratified_split_no_payload_leakage():
    """Splitting by payload means a payload can't appear in two splits."""
    # Same payload under two different contexts — must end up in ONE split.
    pairs = []
    for i in range(40):
        pairs.append(_pair("c1", "html_body", f"<svg onload=alert({i})>"))
        pairs.append(_pair("c2", "attr_dq", f"<svg onload=alert({i})>"))
    splits = stratified_split(pairs, seed=0)
    leaked = check_leakage(splits["train"], splits["test"])
    assert leaked == []


def test_stratified_split_keeps_cross_context_pairs():
    """A payload that appears under multiple contexts is NOT dropped — all its
    pairs stay together in the same split. This preserves cross-context signal."""
    payload = "<svg onload=alert(1)>"
    pairs = [
        _pair("c1", "html_body", payload),
        _pair("c2", "attr_dq", payload),
        _pair("c3", "js_string_sq", payload),
        # enough other payloads to force the shared one into train
        *(_pair(f"o{i}", "html_body", f"<img src=x onerror=alert({i})>") for i in range(60)),
    ]
    splits = stratified_split(pairs, seed=0)
    # The shared payload's pairs must all be in the same split.
    locations = set()
    for name in ("train", "val", "test"):
        for p in splits[name]:
            if normalize_for_dedup(p.payload) == normalize_for_dedup(payload):
                locations.add(name)
    assert len(locations) == 1, f"shared payload landed in multiple splits: {locations}"
    # And all 3 cross-context pairs survived.
    assert sum(1 for name in ("train", "val", "test")
               for p in splits[name]
               if normalize_for_dedup(p.payload) == normalize_for_dedup(payload)) == 3


def test_stratified_split_preserves_total_count():
    """No data loss: every input pair appears in exactly one split."""
    pairs = [_pair(f"c{i % 5}", "html_body", f"payload-{i}") for i in range(100)]
    splits = stratified_split(pairs, seed=0)
    total = sum(len(v) for v in splits.values())
    assert total == 100
