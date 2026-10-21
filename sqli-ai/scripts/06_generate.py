#!/usr/bin/env python
"""SQLi-Gen CLI: generate SQLi payloads for a given injection context."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

def main() -> int:
    parser = argparse.ArgumentParser(prog="sqli-gen", description="Generate SQLi payloads.")
    parser.add_argument("description", nargs="?", default=None)
    parser.add_argument("--context-id", default=None)
    parser.add_argument("--list-contexts", action="store_true")
    parser.add_argument("--model-path", default=None)
    parser.add_argument("-n", type=int, default=5)
    parser.add_argument("--greedy", action="store_true")
    parser.add_argument("--temperature", type=float, default=0.7)
    parser.add_argument("--top-p", type=float, default=0.9)
    args = parser.parse_args()

    yaml_path = ROOT / "data" / "contexts" / "sqli_contexts.yaml"
    if args.list_contexts:
        from sqli_ai.context import ContextSpec, render_description
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        for raw in data.get("contexts", []):
            ctx = ContextSpec(**raw)
            print(f"  {ctx.id}")
            print(f"    {render_description(ctx)}\n")
        return 0

    if args.description:
        description = args.description
    elif args.context_id:
        from sqli_ai.context import ContextSpec, render_description
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        description = None
        for raw in data.get("contexts", []):
            if raw["id"] == args.context_id:
                description = render_description(ContextSpec(**raw))
                break
        if not description:
            print(f"error: unknown context-id '{args.context_id}'"); sys.exit(1)
    else:
        print("error: provide a description or --context-id"); sys.exit(1)

    model_path = args.model_path or str(ROOT / "models" / "sqli-qwen1.5b-v1" / "final")
    print("[sqli-gen] loading model...", file=sys.stderr)
    from sqli_ai.generate import generate, load_model
    model, tokenizer = load_model(model_path)
    strategy = "greedy" if args.greedy else "sampling"
    print(f"[sqli-gen] generating {args.n} ({strategy})...", file=sys.stderr)
    print(f"[sqli-gen] context: {description[:80]}", file=sys.stderr)
    print(file=sys.stderr)
    payloads = generate(model, tokenizer, description, strategy=strategy, n=args.n,
                        temperature=args.temperature, top_p=args.top_p)
    if not payloads:
        print("(no payloads generated)", file=sys.stderr); return 1
    for p in payloads:
        print(p)
    return 0

if __name__ == "__main__":
    sys.exit(main())
