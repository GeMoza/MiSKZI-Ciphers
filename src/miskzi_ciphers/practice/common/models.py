from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PracticeStep:
    index: int
    input_value: str
    output_value: str
    formula: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    comment: str = ""


@dataclass
class PracticeTable:
    title: str
    columns: list[str]
    rows: list[dict[str, Any]]


@dataclass
class HistogramEntry:
    symbol: str
    absolute_count: int
    relative_frequency: float


@dataclass
class HistogramData:
    title: str
    total_count: int
    entries: list[HistogramEntry]


@dataclass
class PracticeResult:
    practice_id: str
    algorithm_id: str
    operation: str
    input_text: str
    output_text: str
    normalized_text: str
    parameters: dict[str, Any] = field(default_factory=dict)
    steps: list[PracticeStep] = field(default_factory=list)
    tables: list[PracticeTable] = field(default_factory=list)
    histograms: list[HistogramData] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
