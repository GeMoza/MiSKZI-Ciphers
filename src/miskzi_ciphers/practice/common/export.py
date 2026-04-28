from __future__ import annotations

from dataclasses import asdict
from typing import Any

from miskzi_ciphers.practice.common.models import HistogramData, PracticeResult, PracticeTable


def practice_result_to_markdown(result: PracticeResult) -> str:
    lines: list[str] = [
        f"# Practice result: {result.practice_id}",
        "",
        f"- Algorithm: `{result.algorithm_id}`",
        f"- Operation: `{result.operation}`",
        "",
        "## Parameters",
        "",
    ]
    lines.extend(_format_mapping_markdown(result.parameters))
    lines.extend(
        [
            "",
            "## Text",
            "",
            f"- Input: `{result.input_text}`",
            f"- Normalized: `{result.normalized_text}`",
            f"- Output: `{result.output_text}`",
            "",
        ]
    )
    lines.extend(_format_steps_markdown(result))
    lines.extend(_format_tables_markdown(result.tables))
    lines.extend(_format_histograms_markdown(result.histograms))
    lines.extend(_format_notes_markdown(result.notes))
    return "\n".join(lines).rstrip() + "\n"


def practice_result_to_text(result: PracticeResult) -> str:
    lines: list[str] = [
        f"Practice result: {result.practice_id}",
        f"Algorithm: {result.algorithm_id}",
        f"Operation: {result.operation}",
        "",
        "Parameters:",
    ]
    lines.extend(_format_mapping_text(result.parameters))
    lines.extend(
        [
            "",
            "Text:",
            f"Input: {result.input_text}",
            f"Normalized: {result.normalized_text}",
            f"Output: {result.output_text}",
            "",
        ]
    )
    lines.extend(_format_steps_text(result))
    lines.extend(_format_tables_text(result.tables))
    lines.extend(_format_histograms_text(result.histograms))
    lines.extend(_format_notes_text(result.notes))
    return "\n".join(lines).rstrip() + "\n"


def _format_mapping_markdown(values: dict[str, Any]) -> list[str]:
    if not values:
        return ["- none"]
    return [f"- `{key}`: `{value}`" for key, value in values.items()]


def _format_mapping_text(values: dict[str, Any]) -> list[str]:
    if not values:
        return ["- none"]
    return [f"- {key}: {value}" for key, value in values.items()]


def _format_steps_markdown(result: PracticeResult) -> list[str]:
    lines = ["## Steps", ""]
    if not result.steps:
        return lines + ["No steps.", ""]
    lines.append("| # | Input | Formula | Output | Comment |")
    lines.append("| --- | --- | --- | --- | --- |")
    for step in result.steps:
        lines.append(
            _markdown_row(
                [
                    step.index,
                    step.input_value,
                    step.formula,
                    step.output_value,
                    step.comment,
                ]
            )
        )
    lines.append("")
    return lines


def _format_steps_text(result: PracticeResult) -> list[str]:
    lines = ["Steps:"]
    if not result.steps:
        return lines + ["No steps.", ""]
    for step in result.steps:
        suffix = f" ({step.comment})" if step.comment else ""
        lines.append(
            f"{step.index}. {step.input_value} -> {step.output_value}; "
            f"{step.formula}{suffix}"
        )
    lines.append("")
    return lines


def _format_tables_markdown(tables: list[PracticeTable]) -> list[str]:
    lines = ["## Tables", ""]
    if not tables:
        return lines + ["No tables.", ""]
    for table in tables:
        lines.extend([f"### {table.title}", ""])
        lines.append("| " + " | ".join(table.columns) + " |")
        lines.append("| " + " | ".join("---" for _ in table.columns) + " |")
        for row in table.rows:
            lines.append(_markdown_row([row.get(column, "") for column in table.columns]))
        lines.append("")
    return lines


def _format_tables_text(tables: list[PracticeTable]) -> list[str]:
    lines = ["Tables:"]
    if not tables:
        return lines + ["No tables.", ""]
    for table in tables:
        lines.append(table.title)
        lines.append(", ".join(table.columns))
        for row in table.rows:
            lines.append(", ".join(str(row.get(column, "")) for column in table.columns))
        lines.append("")
    return lines


def _format_histograms_markdown(histograms: list[HistogramData]) -> list[str]:
    lines = ["## Histograms", ""]
    if not histograms:
        return lines + ["No histograms.", ""]
    for histogram in histograms:
        lines.extend(
            [
                f"### {histogram.title}",
                "",
                "| Symbol | Count | Frequency |",
                "| --- | --- | --- |",
            ]
        )
        for entry in histogram.entries:
            lines.append(
                _markdown_row(
                    [
                        entry.symbol,
                        entry.absolute_count,
                        f"{entry.relative_frequency:.6f}",
                    ]
                )
            )
        lines.append("")
    return lines


def _format_histograms_text(histograms: list[HistogramData]) -> list[str]:
    lines = ["Histograms:"]
    if not histograms:
        return lines + ["No histograms.", ""]
    for histogram in histograms:
        lines.append(histogram.title)
        for entry in histogram.entries:
            lines.append(f"{entry.symbol}: {entry.absolute_count} ({entry.relative_frequency:.6f})")
        lines.append("")
    return lines


def _format_notes_markdown(notes: list[str]) -> list[str]:
    lines = ["## Notes", ""]
    if not notes:
        return lines + ["- none"]
    return lines + [f"- {note}" for note in notes]


def _format_notes_text(notes: list[str]) -> list[str]:
    lines = ["Notes:"]
    if not notes:
        return lines + ["- none"]
    return lines + [f"- {note}" for note in notes]


def practice_result_to_dict(result: PracticeResult) -> dict[str, Any]:
    return asdict(result)


def _markdown_row(values: list[Any]) -> str:
    return "| " + " | ".join(f"`{value}`" for value in values) + " |"
