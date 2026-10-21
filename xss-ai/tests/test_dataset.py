import json

from xss_ai.dataset import XSSDataset


def _make_fake_tokenizer():
    """A minimal fake tokenizer that splits on characters for deterministic testing."""
    class _TokWrapper:
        eos_token = "<|endoftext|>"
        eos_token_id = 0

        def __call__(self, text, **kwargs):
            ids = [ord(c) for c in text if ord(c) < 256]
            return {"input_ids": ids, "attention_mask": [1] * len(ids)}

    return _TokWrapper()


def test_dataset_loads_jsonl(tmp_path):
    f = tmp_path / "test.jsonl"
    f.write_text(json.dumps({
        "id": "x1",
        "context": {"id": "c", "location": "html_body", "description": "desc"},
        "payload": "<svg onload=alert(1)>",
        "provenance": {"source": "browser_oracle", "verified_by": "playwright"},
    }) + "\n")
    tok = _make_fake_tokenizer()
    ds = XSSDataset(f, tok, max_length=512)
    assert len(ds) == 1


def test_dataset_masks_prompt_tokens(tmp_path):
    """Labels should be -100 for prompt tokens and real IDs for payload tokens."""
    f = tmp_path / "test.jsonl"
    f.write_text(json.dumps({
        "id": "x1",
        "context": {"id": "c", "location": "html_body", "description": "Input is reflected."},
        "payload": "AB",
        "provenance": {"source": "browser_oracle", "verified_by": "playwright"},
    }) + "\n")
    tok = _make_fake_tokenizer()
    ds = XSSDataset(f, tok, max_length=512)
    item = ds[0]

    assert "input_ids" in item
    assert "attention_mask" in item
    assert "labels" in item
    assert len(item["input_ids"]) == len(item["labels"])

    # The payload chars "AB" should have real labels (ord('A'), ord('B'))
    non_masked = [l for l in item["labels"] if l != -100]
    assert len(non_masked) >= 2  # at least 'A', 'B'
    assert ord("A") in non_masked
    assert ord("B") in non_masked


def test_dataset_max_length_truncation(tmp_path):
    f = tmp_path / "test.jsonl"
    f.write_text(json.dumps({
        "id": "x1",
        "context": {"id": "c", "location": "html_body", "description": "A" * 200},
        "payload": "B" * 200,
        "provenance": {"source": "browser_oracle", "verified_by": "playwright"},
    }) + "\n")
    tok = _make_fake_tokenizer()
    ds = XSSDataset(f, tok, max_length=64)
    item = ds[0]
    assert len(item["input_ids"]) <= 64


def test_dataset_creates_collator():
    from xss_ai.dataset import create_data_collator
    collator = create_data_collator()
    # Collator pads input_ids and labels to the same length within a batch
    batch = [
        {"input_ids": [1, 2, 3], "attention_mask": [1, 1, 1], "labels": [-100, 2, 3]},
        {"input_ids": [4, 5], "attention_mask": [1, 1], "labels": [4, 5]},
    ]
    result = collator(batch)
    assert result["input_ids"].shape[0] == 2  # batch size
    # Padded to max length in batch (3)
    assert result["input_ids"].shape[1] == 3


def test_dataset_max_per_context_caps_groups(tmp_path):
    """When max_per_context > 0, each context.id gets at most that many pairs."""
    f = tmp_path / "test.jsonl"
    lines = []
    # Context "c1" has 10 pairs, "c2" has 5 pairs
    for i in range(10):
        lines.append(json.dumps({
            "id": f"x1-{i}", "context": {"id": "c1", "location": "html_body", "description": "d"},
            "payload": f"<svg onload=alert({i})>",
            "provenance": {"source": "browser_oracle", "verified_by": "playwright"},
        }))
    for i in range(5):
        lines.append(json.dumps({
            "id": f"x2-{i}", "context": {"id": "c2", "location": "html_body", "description": "d"},
            "payload": f"<img onerror=alert({i})>",
            "provenance": {"source": "browser_oracle", "verified_by": "playwright"},
        }))
    f.write_text("\n".join(lines) + "\n")
    tok = _make_fake_tokenizer()
    ds = XSSDataset(f, tok, max_length=512, max_per_context=3, seed=0)
    # c1 capped to 3, c2 has 5 > 3 so also capped to 3 -> total 6
    assert len(ds) == 6


def test_dataset_max_per_context_zero_means_no_cap(tmp_path):
    """max_per_context=0 (default) means no capping."""
    f = tmp_path / "test.jsonl"
    lines = []
    for i in range(20):
        lines.append(json.dumps({
            "id": f"x-{i}", "context": {"id": "c1", "location": "html_body", "description": "d"},
            "payload": f"<svg onload=alert({i})>",
            "provenance": {"source": "browser_oracle", "verified_by": "playwright"},
        }))
    f.write_text("\n".join(lines) + "\n")
    tok = _make_fake_tokenizer()
    ds = XSSDataset(f, tok, max_length=512, max_per_context=0)
    assert len(ds) == 20
