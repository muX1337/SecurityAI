# XXE-AI: Context-Aware XXE Payload Generation

## Goal

Fine-tune Qwen2.5-1.5B (LoRA) to generate effective XXE payloads conditioned on a
structured description of the XML injection context (location + server-side filters).

**Prompt format** (identical to SSRF/XSS scaffold):
```
### Context:
{context description}

### Payload:
{payload}
```

Loss is computed only on the payload portion (completion-only masking).

## Context taxonomy

### Locations (XML injection points)
- `xml_body` — input is placed inside an XML element body
- `xml_attribute` — input is placed inside an XML attribute value
- `xml_cdata` — input is inside CDATA
- `soap_body` — input is in a SOAP request body
- `svg_upload` — input is an uploaded SVG file content

### Filters (server-side defenses)
- `block_doctype` — blocks `<!DOCTYPE` declarations
- `block_entity` — blocks `<!ENTITY` declarations
- `block_external_entity` — blocks `SYSTEM` keyword in entities
- `block_parameter_entity` — blocks `%` parameter entities
- `block_file_protocol` — blocks `file://` in entity URLs
- `block_http_protocol` — blocks `http://` in entity URLs
- `strip_comments` — removes `<!-- -->` comments
- `disable_dtd` — DTD processing is disabled entirely (strongest defense)

## Oracle design

Python stdlib XML parsers disable XXE by default, so the oracle uses a **structural
check**: the payload is injected into the context's reflection template, filters are
applied, and the resulting XML is inspected for well-formedness and the presence of
an entity definition referencing external content (`SYSTEM`/`PUBLIC`), or a parameter
entity-based OOB pattern. If the structure is intact and the dangerous entity survives
the filters, the XXE "fires."

For OOB payloads referencing an external DTD/URL, the oracle also rewrites the URL to a
local HTTP listener (reusing the SSRF callback pattern) and checks for a callback hit.

## Pipeline (scripts)
1. `01_fetch_corpora.py` — optional external corpus clone (built-ins always available)
2. `02_build_pairs.py` — filter harness → `pairs_raw.jsonl`
3. `03_validate_pairs.py` — oracle agreement gate (85%)
4. `04_finalize_splits.py` — stratified split + quality gates → train/val/test
5. `05_train.py` — LoRA fine-tune Qwen2.5-1.5B
6. `06_generate.py` — CLI payload generation
7. `07_evaluate.py` — T1 (synthetic) + T2 (held-out) + metrics

## Quality gates (Section 2)
- Context balance: no single context > 8% of train
- Dedup: no duplicate (payload, context) pairs
- Leakage: no test payload in train
- Volume: ≥ 500 train pairs
- Contexts: ≥ 10 distinct contexts

## Eval targets
- T1 Synthetic: ≥ 60%
- T2 Held-out combos: ≥ 30%
- Valid XML structure rate: ≥ 90%
- Diversity: ≥ 0.70
- Refusal: ~0%
