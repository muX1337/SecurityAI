"""Tests for the xss-gen CLI (argument parsing + context lookup, no model loading)."""
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from xss_ai.cli import build_parser, list_contexts, resolve_description


def test_build_parser_accepts_freeform_description():
    parser = build_parser()
    args = parser.parse_args(["Input reflected into HTML body"])
    assert args.description == "Input reflected into HTML body"
    assert args.context_id is None
    assert args.list_contexts is False


def test_build_parser_accepts_context_id():
    parser = build_parser()
    args = parser.parse_args(["--context-id", "html-body-plain"])
    assert args.context_id == "html-body-plain"
    assert args.description is None


def test_build_parser_defaults():
    parser = build_parser()
    args = parser.parse_args(["some description"])
    assert args.n == 5
    assert args.greedy is False
    assert args.temperature == 0.7
    assert args.top_p == 0.9


def test_build_parser_greedy_flag():
    parser = build_parser()
    args = parser.parse_args(["desc", "--greedy"])
    assert args.greedy is True


def test_build_parser_n_flag():
    parser = build_parser()
    args = parser.parse_args(["desc", "-n", "10"])
    assert args.n == 10


def test_resolve_description_freeform():
    """Freeform description is returned as-is."""
    args = MagicMock()
    args.description = "Input reflected into HTML body, < and > stripped"
    args.context_id = None
    desc = resolve_description(args, Path("data/contexts/contexts.yaml"))
    assert desc == "Input reflected into HTML body, < and > stripped"


def test_resolve_description_context_id():
    """--context-id loads from YAML and renders the description."""
    args = MagicMock()
    args.description = None
    args.context_id = "html-body-plain"
    desc = resolve_description(args, Path("data/contexts/contexts.yaml"))
    assert "HTML body" in desc
    assert len(desc) > 0


def test_resolve_description_unknown_context_id():
    """Unknown context-id exits with error."""
    args = MagicMock()
    args.description = None
    args.context_id = "does-not-exist"
    with pytest.raises(SystemExit):
        resolve_description(args, Path("data/contexts/contexts.yaml"))


def test_resolve_description_freeform_takes_precedence():
    """If both description and context_id given, freeform wins."""
    args = MagicMock()
    args.description = "My freeform text"
    args.context_id = "html-body-plain"
    desc = resolve_description(args, Path("data/contexts/contexts.yaml"))
    assert desc == "My freeform text"


def test_list_contexts_prints_ids_and_descriptions(capsys):
    yaml_path = Path("data/contexts/contexts.yaml")
    list_contexts(yaml_path)
    captured = capsys.readouterr()
    assert "html-body-plain" in captured.out
    assert "attr-dq-plain" in captured.out
    # Should print multiple contexts
    lines = [l for l in captured.out.strip().split("\n") if l.strip()]
    assert len(lines) >= 10
