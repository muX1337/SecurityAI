#!/usr/bin/env python
"""SSTI-Gen CLI: generate SSTI payloads for a given injection context."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def main() -> int:
    parser = argparse.ArgumentParser(prog="ssti-gen", description="Generate SSTI payloads.")
    parser.add_argument("description", nargs="?", default=None,
                        help="freeform description of the SSTI context")
    parser.add_argument("--context-id", default=None,
                        help="predefined context ID from the taxonomy")
    parser.add_argument("--list-contexts", action="store_true")
    parser.add_argument("--model-path", default=None)
    parser.add_argument("-n", type=int, default=5)
    parser.add_argument("--greedy", action="store_true")
    parser.add_argument("--temperature", type=float, default=0.7)
    parser.add_argument("--top-p", type=float, default=0.9)
    args = parser.parse_args()

    yaml_path = ROOT / "data" / "contexts" / "ssti_contexts.yaml"

    if args.list_contexts:
        from ssti_ai.context import ContextSpec, render_description
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        for raw in data.get("contexts", []):
            ctx = ContextSpec(**raw)
            print(f"  {ctx.id}")
            print(f"    {render_description(ctx)}")
            print()
        return 0

    # Resolve description
    if args.description:
        description = args.description
    elif args.context_id:
        from ssti_ai.context import ContextSpec, render_description
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        description = None
        for raw in data.get("contexts", []):
            if raw["id"] == args.context_id:
                ctx = ContextSpec(**raw)
                description = render_description(ctx)
                break
        if not description:
            print(f"error: unknown context-id '{args.context_id}'")
            sys.exit(1)
    else:
        print("error: provide a description or --context-id")
        sys.exit(1)

    # Find model
    model_path = args.model_path or str(ROOT / "models" / "ssti-qwen1.5b-v1" / "final")

    print(f"[ssti-gen] loading model from {model_path}...", file=sys.stderr)
    from ssti_ai.generate import generate, load_model
    model, tokenizer = load_model(model_path)

    strategy = "greedy" if args.greedy else "sampling"
    print(f"[ssti-gen] generating {args.n} payload(s) ({strategy})...", file=sys.stderr)
    print(f"[ssti-gen] context: {description[:80]}", file=sys.stderr)
    print(file=sys.stderr)

    payloads = generate(model, tokenizer, description, strategy=strategy, n=args.n,
                        temperature=args.temperature, top_p=args.top_p)

    if not payloads:
        print("(no payloads generated)", file=sys.stderr)
        return 1

    for payload in payloads:
        print(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
