"""Report generation: eval results -> JSON + markdown summary."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path


def generate_report(results: dict, output_dir: Path) -> None:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    results = {**results, "timestamp": datetime.now(UTC).isoformat()}
    json_path = output_dir / "eval_report.json"
    json_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    md_path = output_dir / "eval_report.md"
    md_path.write_text(format_markdown(results), encoding="utf-8")


def format_markdown(results: dict) -> str:
    lines: list[str] = []
    lines.append("# CMDi-AI Evaluation Report")
    lines.append("")
    lines.append(f"**Model:** `{results.get('model_path', 'unknown')}`")
    lines.append(f"**Date:** {results.get('timestamp', 'N/A')}")
    lines.append("")

    t1 = results.get("t1", {})
    t2 = results.get("t2", {})
    sec = results.get("secondary", {})

    lines.append("## Summary")
    lines.append("")
    lines.append("| Tier | Rate | Target | Status |")
    lines.append("|------|------|--------|--------|")
    _row(lines, "T1 Synthetic", t1.get("rate", 0), t1.get("target", 0.60), t1.get("passed", False))
    _row(lines, "T2 Held-out", t2.get("rate", 0), t2.get("target", 0.30), t2.get("passed", False))
    _row(lines, "Valid CMD", sec.get("valid_cmd_rate", 0), sec.get("cmd_target", 0.90), sec.get("cmd_passed", False))
    _row(lines, "Diversity", sec.get("diversity_score", 0), sec.get("diversity_target", 0.70), sec.get("diversity_passed", False))
    lines.append(f"| Refusal Rate | {sec.get('refusal_rate', 0):.1%} | ~0% | {'✅' if sec.get('refusal_rate', 1) < 0.05 else '⚠️'} |")
    lines.append("")

    if t1.get("per_context"):
        lines.append("## T1: Per-Context Breakdown")
        lines.append("")
        lines.append("| Context | Fired | Total | Rate |")
        lines.append("|---------|-------|-------|------|")
        for ctx_id, stats in sorted(t1["per_context"].items(), key=lambda x: -x[1]["rate"]):
            lines.append(f"| {ctx_id} | {stats['fired']} | {stats['total']} | {stats['rate']:.1%} |")
        lines.append("")

    all_failures = t1.get("failures", []) + t2.get("failures", [])
    if all_failures:
        lines.append("## Failure Log")
        lines.append("")
        lines.append("| Context | Payload | Reason |")
        lines.append("|---------|---------|--------|")
        for f in all_failures:
            payload = f.get("payload", "")[:60].replace("|", "\\|")
            lines.append(f"| {f.get('context_id', '?')} | `{payload}` | {f.get('reason', '?')} |")
        lines.append("")

    return "\n".join(lines)


def _row(lines: list[str], name: str, rate: float, target: float, passed: bool) -> None:
    status = "✅ PASS" if passed else "❌ FAIL"
    lines.append(f"| {name} | {rate:.1%} | {target:.0%} | {status} |")
