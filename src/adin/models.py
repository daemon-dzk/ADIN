"""Shared result models used by detectors and the analysis pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


def confidence_label(score: float) -> str:
    if score >= 0.90:
        return "very high"
    if score >= 0.75:
        return "high"
    if score >= 0.55:
        return "moderate"
    return "low"


@dataclass
class Detection:
    name: str
    category: str
    score: float
    description: str
    evidence: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    parameters: dict[str, Any] = field(default_factory=dict)
    decoded_preview: str | None = None
    decoded_bytes: bytes | None = field(default=None, repr=False, compare=False)
    detector: str = "unknown"

    @property
    def confidence(self) -> str:
        return confidence_label(self.score)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "name": self.name,
            "category": self.category,
            "confidence": self.confidence,
            "confidence_score": round(self.score, 3),
            "description": self.description,
            "evidence": self.evidence,
            "limitations": self.limitations,
            "parameters": self.parameters,
            "detector": self.detector,
        }
        if self.decoded_preview is not None:
            out["decoded_preview"] = self.decoded_preview
        if self.decoded_bytes is not None:
            out["decoded_length_bytes"] = len(self.decoded_bytes)
        return out


@dataclass
class AnalysisLayer:
    index: int
    byte_length: int
    statistics: dict[str, Any]
    detections: list[Detection]
    transition: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "byte_length": self.byte_length,
            "statistics": self.statistics,
            "transition": self.transition,
            "detections": [d.to_dict() for d in self.detections],
        }


@dataclass
class AnalysisReport:
    input_length: int
    input_sha256: str
    source: str
    layers: list[AnalysisLayer]
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "ADIN",
            "version": "0.1.0",
            "source": self.source,
            "input": {"length_bytes": self.input_length, "sha256": self.input_sha256},
            "layers": [layer.to_dict() for layer in self.layers],
            "warnings": self.warnings,
        }
