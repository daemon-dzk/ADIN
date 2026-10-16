"""Fast, bounded, deterministic analysis pipeline."""
from __future__ import annotations

import hashlib
import math
import zlib
from collections import Counter
from typing import Iterable

from .detectors.encodings import detect_encodings
from .detectors.formats import detect_crypto_formats
from .models import AnalysisLayer, AnalysisReport, Detection
from .util import looks_like_text, shannon_entropy


def _statistics(data: bytes) -> dict:
    if not data:
        return {"entropy_bits_per_byte": 0.0, "unique_byte_values": 0, "printable_ratio": 1.0,
                "nul_bytes": 0, "text_utf8": True}
    printable = sum(1 for b in data if b in (9, 10, 13) or 32 <= b <= 126)
    try:
        data.decode("utf-8")
        utf8 = True
    except UnicodeDecodeError:
        utf8 = False
    return {
        "entropy_bits_per_byte": round(shannon_entropy(data), 4),
        "unique_byte_values": len(set(data)),
        "printable_ratio": round(printable / len(data), 4),
        "nul_bytes": data.count(b"\x00"),
        "text_utf8": utf8,
    }


def _extra_binary_detections(data: bytes) -> list[Detection]:
    found: list[Detection] = []
    # Unicode BOMs identify UTF encodings directly; alternating NULs can only suggest them.
    bom_encodings = [(b"\x00\x00\xfe\xff", "UTF-32 big-endian", "utf-32-be"),
                     (b"\xff\xfe\x00\x00", "UTF-32 little-endian", "utf-32-le"),
                     (b"\xfe\xff", "UTF-16 big-endian", "utf-16-be"),
                     (b"\xff\xfe", "UTF-16 little-endian", "utf-16-le"),
                     (b"\xef\xbb\xbf", "UTF-8 with BOM", "utf-8-sig")]
    for bom, label, codec in bom_encodings:
        if data.startswith(bom):
            try:
                text = data.decode(codec)
                found.append(Detection(name=label, category="text_encoding", score=0.99,
                    description=f"The input begins with the byte-order mark commonly used for {label}.",
                    evidence=[f"Recognized BOM: {bom.hex()}"],
                    limitations=["A BOM identifies a Unicode encoding convention but does not guarantee all remaining content is meaningful text."],
                    parameters={"codec": codec}, decoded_bytes=text.encode("utf-8"), detector="unicode"))
            except UnicodeDecodeError:
                pass
            break
    if not any(d.detector == "unicode" for d in found) and len(data) >= 4 and len(data) % 2 == 0:
        even_nuls = sum(1 for i in range(0, len(data), 2) if data[i] == 0)
        odd_nuls = sum(1 for i in range(1, len(data), 2) if data[i] == 0)
        pairs = len(data) // 2
        codec = None
        label = None
        if odd_nuls / pairs >= 0.35 and even_nuls / pairs < 0.1:
            codec, label = "utf-16le", "UTF-16 little-endian candidate"
        elif even_nuls / pairs >= 0.35 and odd_nuls / pairs < 0.1:
            codec, label = "utf-16be", "UTF-16 big-endian candidate"
        if codec:
            try:
                text = data.decode(codec)
                if text and sum(ch.isprintable() or ch in "\r\n\t" for ch in text) / len(text) >= 0.8:
                    found.append(Detection(name=label, category="text_encoding", score=0.78,
                        description="Alternating NUL bytes suggest a UTF-16 text representation.",
                        evidence=[f"NUL byte ratio: even offsets={even_nuls/pairs:.1%}, odd offsets={odd_nuls/pairs:.1%}.", "Decoded characters are predominantly printable."],
                        limitations=["This is a heuristic; binary data can coincidentally have the same byte pattern."],
                        parameters={"codec": codec}, decoded_bytes=text.encode("utf-8"), detector="unicode"))
            except UnicodeDecodeError:
                pass
    # zlib wrapper: RFC 1950 CMF/FLG consistency check; intentionally do not decompress.
    if len(data) >= 6 and data[0] & 0x0F == 8 and ((data[0] << 8) + data[1]) % 31 == 0 and data[1] & 0x20 == 0:
        found.append(Detection(
            name="zlib-wrapped compressed stream candidate", category="compression", score=0.78,
            description="The bytes resemble an RFC 1950 zlib wrapper around compressed data.",
            evidence=["Compression method nibble indicates DEFLATE.", "The CMF/FLG header check modulo 31 passes."],
            limitations=["This is a header-only check; the stream was not decompressed or validated."],
            parameters={"header_hex": data[:2].hex()}, detector="binary-statistics"))
    # Entropy is supporting context only, never proof of encryption.
    entropy = shannon_entropy(data)
    if len(data) >= 32 and entropy >= 7.5:
        found.append(Detection(
            name="High-entropy bytes", category="statistical_observation", score=0.58,
            description="The byte distribution is close to uniform in this sample.",
            evidence=[f"Shannon entropy is {entropy:.3f} bits per byte across {len(data)} bytes."],
            limitations=["High entropy can arise from encryption, compression, randomness, or a short/unrepresentative sample; it cannot identify an algorithm."],
            parameters={"entropy_bits_per_byte": round(entropy, 4)}, detector="statistics"))
    return found


def _rank(detections: Iterable[Detection]) -> list[Detection]:
    # Stable sort retains detector ordering when scores tie.
    return sorted(detections, key=lambda d: d.score, reverse=True)


def _choose_transition(detections: list[Detection], current: bytes, seen: set[str]) -> Detection | None:
    # Preserve primary structured interpretations; a generic alphabet can also accept their text bytes.
    primary_categories = {"encrypted_data_container", "cryptographic_container", "signed_token", "encrypted_token", "password_hash", "public_key", "key_fingerprint", "archive", "compression", "binary_format"}
    if any(d.score >= 0.90 and d.category in primary_categories for d in detections):
        return None
    possible_hash = any(d.category == "possible_hash" for d in detections)
    # Hex digests also happen to use the Base64 alphabet; don't recursively decode a
    # digest-shaped value just because one of the overlapping alphabets accepts it.
    try:
        current_text = current.decode("ascii").strip()
    except UnicodeDecodeError:
        current_text = ""
    if possible_hash and len(current_text) in (32, 40, 56, 64, 96, 128) and current_text and all(c in "0123456789abcdefABCDEF" for c in current_text):
        return None
    for det in _rank(detections):
        if det.decoded_bytes is None or det.score < 0.74:
            continue
        if det.category not in ("encoding", "text_encoding"):
            continue
        if det.name.startswith("Hexadecimal") and possible_hash:
            # Avoid walking a likely digest through a meaningless binary representation.
            continue
        candidate = det.decoded_bytes
        if candidate == current or not candidate:
            continue
        fp = hashlib.sha256(candidate).hexdigest()
        if fp in seen:
            continue
        # Do not follow degenerate transformations which barely change a long input.
        if len(candidate) > 0 and candidate == current:
            continue
        return det
    return None


def analyze(data: bytes, source: str = "argument", max_depth: int = 3, max_bytes: int = 1_048_576) -> AnalysisReport:
    if len(data) > max_bytes:
        raise ValueError(f"input is {len(data)} bytes; configured limit is {max_bytes} bytes")
    if max_depth < 0 or max_depth > 10:
        raise ValueError("depth must be between 0 and 10")

    original = bytes(data)
    original_hash = hashlib.sha256(original).hexdigest()
    current = original
    layers: list[AnalysisLayer] = []
    warnings: list[str] = []
    seen = {original_hash}

    if not original:
        warnings.append("Input is empty; there is no content to classify.")

    for layer_index in range(max_depth + 1):
        detections: list[Detection] = []
        detections.extend(detect_crypto_formats(current))
        detections.extend(detect_encodings(current))
        detections.extend(_extra_binary_detections(current))
        detections = _rank(detections)
        transition = None
        if layer_index < max_depth:
            choice = _choose_transition(detections, current, seen)
            if choice is not None:
                next_data = choice.decoded_bytes
                assert next_data is not None
                transition = f"Decoded by {choice.name} ({choice.confidence} confidence)"
                layers.append(AnalysisLayer(layer_index, len(current), _statistics(current), detections, transition))
                current = next_data
                seen.add(hashlib.sha256(current).hexdigest())
                continue
        layers.append(AnalysisLayer(layer_index, len(current), _statistics(current), detections, None))
        break

    if len(layers) == max_depth + 1 and layers[-1].index == max_depth:
        if _choose_transition(layers[-1].detections, current, seen) is not None:
            warnings.append(f"Maximum decode depth ({max_depth}) reached; further nested analysis was not performed.")
    if len(original) > 0 and not any(layer.detections for layer in layers):
        warnings.append("No supported format was confidently identified. Unknown or custom formats are expected.")
    return AnalysisReport(input_length=len(original), input_sha256=original_hash, source=source, layers=layers, warnings=warnings)
