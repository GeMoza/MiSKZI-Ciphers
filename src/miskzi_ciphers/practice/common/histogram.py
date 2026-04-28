from __future__ import annotations

from collections import Counter

from miskzi_ciphers.practice.common.models import HistogramData, HistogramEntry


def build_histogram(text: str, *, title: str = "Histogram") -> HistogramData:
    total = len(text)
    counts = Counter(text)
    entries = [
        HistogramEntry(
            symbol=symbol,
            absolute_count=count,
            relative_frequency=(count / total if total else 0.0),
        )
        for symbol, count in sorted(counts.items(), key=lambda item: item[0])
    ]
    return HistogramData(title=title, total_count=total, entries=entries)


def compare_histograms(input_text: str, output_text: str) -> tuple[HistogramData, HistogramData]:
    return (
        build_histogram(input_text, title="Input text histogram"),
        build_histogram(output_text, title="Output text histogram"),
    )
