"""xss-gen: interactive CLI for generating XSS payloads with the trained model.

Usage:
    # Freeform — describe the injection context
    xss-gen "Input reflected into HTML body, < and > stripped"

    # Predefined context from the taxonomy
    xss-gen --context-id html-body-strip-ltgt -n 10

    # List available contexts
    xss-gen --list-contexts

    # Greedy (deterministic)
    xss-gen --context-id attr-dq-plain --greedy
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for xss-gen."""
    parser = argparse.ArgumentParser(
        prog="xss-gen",
        description="Generate XSS payloads for a given injection context.",
    )
    parser.add_argument(
        "description",
        nargs="?",
        default=None,
        help="freeform description of the injection context",
    )
    parser.add_argument(
        "--context-id",
        default=None,
        help="predefined context ID from the taxonomy (use --list-contexts to see options)",
    )
    parser.add_argument(
        "--list-contexts",
        action="store_true",
        help="list all available predefined contexts and exit",
    )
    parser.add_argument(
        "--model-path",
        default=None,
        help="path to the merged model directory (default: auto-detect latest v)",
    )
    parser.add_argument(
        "-n",
        type=int,
        default=5,
        help="number of payloads to generate (default: 5)",
    )
    parser.add_argument(
        "--greedy",
        action="store_true",
        help="use greedy decoding (deterministic) instead of sampling",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.7,
        help="sampling temperature (default: 0.7)",
    )
    parser.add_argument(
        "--top-p",
        type=float,
        default=0.9,
        help="nucleus sampling threshold (default: 0.9)",
    )
    return parser


def resolve_description(args: argparse.Namespace, yaml_path: Path) -> str:
    """Resolve the context description from freeform text or predefined context-id.

    Freeform description takes precedence if both are provided.
    """
    if args.description:
        return args.description

    if args.context_id:
        from .context import ContextSpec, render_description

        data = yaml.safe_load(Path(yaml_path).read_text(encoding="utf-8"))
        for raw in data.get("contexts", []):
            if raw["id"] == args.context_id:
                ctx = ContextSpec(**raw)
                return render_description(ctx)

        print(f"error: unknown context-id '{args.context_id}'. Use --list-contexts to see options.")
        sys.exit(1)

    # Neither provided — shouldn't reach here if main() validates, but handle gracefully
    print("error: provide a freeform description or --context-id. Use --help for usage.")
    sys.exit(1)


def list_contexts(yaml_path: Path) -> None:
    """Print all predefined context IDs and their rendered descriptions."""
    from .context import ContextSpec, render_description

    data = yaml.safe_load(Path(yaml_path).read_text(encoding="utf-8"))
    for raw in data.get("contexts", []):
        ctx = ContextSpec(**raw)
        desc = render_description(ctx)
        print(f"  {ctx.id}")
        print(f"    {desc}")
        print()


def _find_model(root: Path) -> Path:
    """Auto-detect the latest merged model directory."""
    models_dir = root / "models"
    if not models_dir.exists():
        return models_dir / "xss-qwen1.5b-v2" / "merged"

    # Look for versioned model dirs, pick the highest version
    candidates = sorted(
        [d for d in models_dir.iterdir()
         if d.is_dir() and d.name.startswith("xss-qwen1.5b-v")]
    )
    for model_dir in reversed(candidates):
        merged = model_dir / "merged"
        if merged.exists():
            return merged
        final = model_dir / "final"
        if final.exists():
            return final

    return models_dir / "xss-qwen1.5b-v2" / "merged"


def main() -> int:
    """Entry point for the xss-gen CLI."""
    parser = build_parser()
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent.parent
    yaml_path = root / "data" / "contexts" / "contexts.yaml"

    # Handle --list-contexts
    if args.list_contexts:
        list_contexts(yaml_path)
        return 0

    # Resolve description
    description = resolve_description(args, yaml_path)

    # Resolve model path
    model_path = args.model_path or str(_find_model(root))

    # Load model (lazy import — torch/transformers are heavy)
    print(f"[xss-gen] loading model from {model_path}...", file=sys.stderr)
    from .generate import generate, load_model

    model, tokenizer = load_model(model_path)

    # Generate
    strategy = "greedy" if args.greedy else "sampling"
    print(f"[xss-gen] generating {args.n} payload(s) ({strategy})...", file=sys.stderr)
    print(f"[xss-gen] context: {description[:80]}", file=sys.stderr)
    print(file=sys.stderr)

    payloads = generate(
        model, tokenizer, description,
        strategy=strategy,
        n=args.n,
        temperature=args.temperature,
        top_p=args.top_p,
    )

    # Print payloads to stdout (stderr has progress info)
    if not payloads:
        print("(no payloads generated)", file=sys.stderr)
        return 1

    for i, payload in enumerate(payloads, 1):
        print(f"{payload}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
