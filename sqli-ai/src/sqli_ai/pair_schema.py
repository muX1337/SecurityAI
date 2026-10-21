"""The Pair record: one (context, working payload) training example."""
from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from .context import ContextSpec


class Provenance(BaseModel):
    source: str  # "filter_harness" | "browser_oracle" | "lab_miner"
    verified_by: str  # "filter_sim" | "playwright" | "none"
    verified_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    def __getitem__(self, key: str) -> str:
        # Dict-style access (e.g. provenance["source"]) for ergonomic reads/tests.
        return getattr(self, key)


class Pair(BaseModel):
    id: str
    context: ContextSpec
    payload: str
    provenance: Provenance

    def to_jsonl(self) -> str:
        return self.model_dump_json()
