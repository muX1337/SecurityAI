import json

import pytest
from xss_ai.eval.report import format_markdown, generate_report


@pytest.fixture
def sample_results():
    return {
        "model_path": "models/xss-qwen1.5b-v1/merged",
        "t1": {
            "total": 100,
            "fired": 65,
            "rate": 0.65,
            "target": 0.60,
            "passed": True,
            "per_context": {
                "html-body-plain": {"total": 20, "fired": 18, "rate": 0.90},
                "html-body-block-script": {"total": 15, "fired": 5, "rate": 0.33},
            },
            "failures": [
                {"context_id": "html-body-block-script", "payload": "<script>alert(1)</script>", "reason": "filtered_to_empty"},
                {"context_id": "html-body-plain", "payload": "hello", "reason": "syntax_invalid"},
            ],
        },
        "t2": {
            "total": 20,
            "fired": 8,
            "rate": 0.40,
            "target": 0.30,
            "passed": True,
            "per_context": {
                "heldout-html-body-strip_parens": {"total": 5, "fired": 2, "rate": 0.40},
            },
            "failures": [],
        },
        "secondary": {
            "valid_syntax_rate": 0.95,
            "syntax_target": 0.90,
            "syntax_passed": True,
            "diversity_score": 0.78,
            "diversity_target": 0.70,
            "diversity_passed": True,
            "refusal_rate": 0.0,
        },
    }

def test_generate_report_writes_json(tmp_path, sample_results):
    out_dir = tmp_path / "report"
    generate_report(sample_results, out_dir)
    json_path = out_dir / "eval_report.json"
    assert json_path.exists()
    data = json.loads(json_path.read_text())
    assert data["t1"]["rate"] == 0.65
    assert data["t2"]["rate"] == 0.40

def test_generate_report_writes_markdown(tmp_path, sample_results):
    out_dir = tmp_path / "report"
    generate_report(sample_results, out_dir)
    md_path = out_dir / "eval_report.md"
    assert md_path.exists()
    md = md_path.read_text()
    assert "T1" in md or "Tier 1" in md
    assert "65%" in md or "0.65" in md
    assert "PASS" in md or "pass" in md.lower()

def test_format_markdown_has_summary_table(tmp_path, sample_results):
    md = format_markdown(sample_results)
    assert "| Tier" in md or "| Metric" in md
    assert "60%" in md  # T1 target
    assert "30%" in md  # T2 target

def test_format_markdown_has_failure_log(tmp_path, sample_results):
    md = format_markdown(sample_results)
    assert "Failure" in md or "failure" in md.lower()
    assert "filtered_to_empty" in md
    assert "html-body-block-script" in md

def test_format_markdown_pass_fail_indicators(tmp_path, sample_results):
    md = format_markdown(sample_results)
    # T1 passed (65% >= 60%)
    assert "✅" in md or "PASS" in md
    # All targets in the fixture pass
    assert "✅" in md

def test_generate_report_creates_directory(tmp_path, sample_results):
    out_dir = tmp_path / "nested" / "report"
    generate_report(sample_results, out_dir)
    assert out_dir.exists()
