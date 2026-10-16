"""Command-line interface for ADIN."""
from __future__ import annotations

import argparse
import json
import os
import sys
import textwrap
from typing import Sequence

from . import __version__
from .models import AnalysisReport, Detection
from .pipeline import analyze
from .util import printable_preview

BANNER = r"""
    _    ____  ___ _   _
   / \  |  _ \|_ _| \ | |
  / _ \ | | | || ||  \| |
 / ___ \| |_| || || |\  |
/_/   \_\____/|___|_| \_|
  Automated Cryptographic Inspector
"""


def _color(text: str, code: str, enabled: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if enabled else text


def _confidence_color(score: float) -> str:
    if score >= 0.75:
        return "32"
    if score >= 0.55:
        return "33"
    return "90"


def _wrapped(label: str, value: str, width: int = 76) -> list[str]:
    """Format a label/value field with aligned wrapped continuation lines."""
    prefix = f"{label:<15}: "
    return textwrap.wrap(
        value,
        width=width,
        initial_indent=prefix,
        subsequent_indent=" " * len(prefix),
        break_long_words=True,
        break_on_hyphens=False,
    ) or [prefix.rstrip()]


def _human_category(category: str) -> str:
    labels = {
        "encoding": "Data Encoding",
        "text_encoding": "Text Encoding",
        "possible_hash": "Possible Hash Digest",
        "password_hash": "Password Hash Format",
        "encrypted_token": "Encrypted Token Format",
        "signed_token": "Signed Token / JWS",
        "cryptographic_container": "Cryptographic Container",
        "encrypted_data_container": "Encrypted Data Container",
        "public_key": "Public Key Format",
        "key_fingerprint": "Key Fingerprint",
        "compression": "Compression Format",
        "binary_format": "Binary / ASN.1 Format",
        "archive": "Archive Format",
        "statistical_observation": "Statistical Observation",
        "classical_cipher_candidate": "Classical Cipher Candidate",
    }
    return labels.get(category, category.replace("_", " ").title() or "Unknown")


def _human_verdict(detection: Detection | None) -> str:
    if detection is None:
        return "UNKNOWN / NOT IDENTIFIED"
    name = detection.name.lower()
    if detection.category == "possible_hash":
        return f"{detection.name.upper()} (CANDIDATE)"
    if detection.category == "password_hash":
        return detection.name.upper()
    known = (
        ("hexadecimal", "HEXADECIMAL ENCODING"),
        ("0x-prefixed hexadecimal", "HEXADECIMAL ENCODING"),
        ("base64 url-safe", "BASE64URL ENCODING"),
        ("base64", "BASE64 ENCODING"),
        ("base32", "BASE32 ENCODING"),
        ("base58check", "BASE58CHECK ENCODING"),
        ("base58", "BASE58 ENCODING CANDIDATE"),
        ("base45", "BASE45 ENCODING"),
        ("base85", "BASE85 ENCODING CANDIDATE"),
        ("asci85", "ASCII85 ENCODING CANDIDATE"),
        ("ascii85", "ASCII85 ENCODING CANDIDATE"),
        ("base91", "BASE91 ENCODING"),
        ("morse", "MORSE CODE CANDIDATE"),
        ("percent / url", "PERCENT / URL ENCODING"),
        ("quoted-printable", "QUOTED-PRINTABLE ENCODING"),
        ("compact jws", "SIGNED JWT / JWS CANDIDATE"),
        ("compact jwe", "ENCRYPTED JWT / JWE CANDIDATE"),
        ("fernet", "FERNET TOKEN CANDIDATE"),
        ("openssl salted", "OPENSSL SALTED-DATA FORMAT CANDIDATE"),
        ("hash", "HASH FORMAT CANDIDATE"),
        ("high-entropy", "HIGH-ENTROPY DATA (ALGORITHM UNKNOWN)"),
    )
    for needle, label in known:
        if needle in name:
            if detection.score < 0.75 and "CANDIDATE" not in label and detection.category == "encoding":
                return label + " CANDIDATE"
            return label
    label = detection.name.upper()
    if detection.score < 0.75 and "CANDIDATE" not in label:
        label += " CANDIDATE"
    return label


def _final_classification(detection: Detection | None) -> str:
    if detection is None:
        return "Inconclusive"
    category = detection.category
    if category in {"encoding", "text_encoding"}:
        return "Encoding, not encryption"
    if category in {"possible_hash", "password_hash"}:
        return "Hash format, not encryption"
    if category == "signed_token":
        return "Signed token; not necessarily encrypted"
    if category in {"encrypted_token", "encrypted_data_container"}:
        return "Encrypted-data format candidate"
    if category == "compression":
        return "Compression, not encryption"
    if category in {"public_key", "key_fingerprint"}:
        return "Key material, not ciphertext"
    if category == "statistical_observation":
        return "Statistical observation; algorithm unknown"
    return _human_category(category)


def _encryption_explanation(detection: Detection | None) -> str:
    if detection is None:
        return "Cannot determine from this input; no supported format was identified."
    category = detection.category
    if category in {"encoding", "text_encoding"}:
        return "No. This is an encoding, not encryption; it can be reversed without a secret key."
    if category in {"possible_hash", "password_hash"}:
        return "No. A hash is a one-way digest used for comparison or verification, not encryption."
    if category == "signed_token":
        return "Usually no. JWS is signed, not encrypted; its payload may be readable. Signature verification was not performed."
    if category in {"encrypted_token", "encrypted_data_container"}:
        return "Possibly. The structure is associated with encrypted data, but this check does not prove the payload is valid or decrypt it."
    if category == "cryptographic_container":
        return "Not enough information. This container format may hold encrypted or signed material; the marker alone is inconclusive."
    if category in {"public_key", "key_fingerprint"}:
        return "No. This appears to be public-key material or its fingerprint, not ciphertext."
    if category == "compression":
        return "No. The detected pattern is associated with compression, not encryption."
    if category == "classical_cipher_candidate":
        return "Possibly a classical cipher, but this is heuristic and is not modern secure encryption."
    if category in {"statistical_observation", "binary_format", "archive"}:
        return "Cannot determine from this signal alone. Entropy or binary structure does not identify encryption."
    return "Cannot determine reliably from this format match alone."


def render_terminal(
    report: AnalysisReport,
    verbose: bool = False,
    color: bool | None = None,
    input_data: bytes | None = None,
) -> str:
    """Render a concise, human-first verdict with evidence-based alternatives."""
    if color is None:
        color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
    c = lambda text, code: _color(text, code, bool(color))
    width = 48
    border_top = "╭" + "─" * width + "╮"
    border_bottom = "╰" + "─" * width + "╯"
    title = "ADIN ANALYSIS".center(width)
    lines = [
        c(border_top, "36;1"),
        c("│" + title + "│", "36;1"),
        c(border_bottom, "36;1"),
        c(f"ADIN v{__version__} | Offline cryptographic & encoding inspector", "36"),
        "",
    ]

    if input_data is None:
        input_preview = "(input preview unavailable in this report view)"
    else:
        from .util import printable_preview
        input_preview = printable_preview(input_data, limit=180)
    lines.extend(_wrapped("INPUT", input_preview))

    first_layer = report.layers[0] if report.layers else None
    detections = first_layer.detections if first_layer else []
    primary = detections[0] if detections else None
    if primary is not None:
        lines.append("")
        lines.extend(_wrapped("VERDICT", _human_verdict(primary)))
        lines.extend(_wrapped("CATEGORY", _human_category(primary.category)))
        confidence = f"{primary.confidence.title()} ({primary.score:.0%})"
        lines.append(c(f"{'CONFIDENCE':<15}: {confidence}", _confidence_color(primary.score)))
        decoded = primary.decoded_preview
        lines.extend(_wrapped("DECODED", decoded if decoded is not None else "Not applicable / no decoded output"))

        lines.append("")
        lines.append(c("WHAT IS IT?", "1;36"))
        lines.extend(textwrap.wrap(primary.description, width=width + 20) or [primary.description])

        lines.append("")
        lines.append(c("IS IT ENCRYPTION?", "1;36"))
        lines.extend(textwrap.wrap(_encryption_explanation(primary), width=width + 20))
    else:
        lines.append("")
        lines.extend(_wrapped("VERDICT", "UNKNOWN / NOT IDENTIFIED"))
        lines.extend(_wrapped("CATEGORY", "Unknown data / no supported pattern"))
        lines.extend(_wrapped("CONFIDENCE", "Inconclusive"))
        lines.extend(_wrapped("DECODED", "No decoding performed"))
        lines.append("")
        lines.append(c("WHAT IS IT?", "1;36"))
        lines.append("ADIN did not find a supported pattern strong enough to report.")
        lines.append("This does not mean the data is invalid or unimportant.")
        lines.append("")
        lines.append(c("IS IT ENCRYPTION?", "1;36"))
        lines.append(_encryption_explanation(None))

    # Show alternate interpretations separately from the main verdict, with caveats.
    alternatives = [d for d in detections[1:] if d.score >= 0.55]
    if alternatives:
        lines.append("")
        lines.append(c("ALTERNATIVE MATCHES", "1;36"))
        display_alternatives = alternatives if verbose else alternatives[:3]
        for det in display_alternatives:
            confidence = f"{det.confidence.title()} ({det.score:.0%})"
            lines.append(f"- {det.name}: {confidence}")
            if det.score < 0.75 and det.limitations:
                detail = det.limitations[0]
            else:
                detail = det.description
            lines.extend(textwrap.wrap(detail, width=width + 16, initial_indent="  ", subsequent_indent="  "))
        if len(alternatives) > len(display_alternatives):
            lines.append(f"  ... {len(alternatives) - len(display_alternatives)} more; use --verbose to show all.")

    lines.append("")
    lines.append(c("FINAL RESULT", "1;36"))
    if primary is None:
        lines.append("Type            : Unknown / not identified")
        lines.append("Data            : Original input preserved; no supported decode")
        lines.append("Classification  : Inconclusive")
    else:
        final_type = _human_verdict(primary)
        final_data = primary.decoded_preview if primary.decoded_preview is not None else "No decoded output available"
        lines.extend(_wrapped("Type", final_type))
        lines.extend(_wrapped("Data", final_data))
        lines.extend(_wrapped("Classification", _final_classification(primary)))

    if len(report.layers) > 1:
        lines.append("")
        lines.extend(_wrapped("DECODE LAYERS", f"{len(report.layers)} layer(s) inspected"))
        if report.layers[0].transition:
            lines.extend(_wrapped("FIRST STEP", report.layers[0].transition))

    if report.warnings:
        lines.append("")
        lines.append(c("NOTES", "1;33"))
        for warning in report.warnings:
            lines.extend(textwrap.wrap("- " + warning, width=width + 20, subsequent_indent="  "))

    if verbose and first_layer:
        lines.append("")
        lines.append(c("TECHNICAL DETAILS", "1;36"))
        lines.extend(_wrapped("SOURCE", report.source))
        lines.extend(_wrapped("INPUT SIZE", f"{report.input_length} bytes"))
        lines.extend(_wrapped("SHA-256", report.input_sha256))
        stats = first_layer.statistics
        lines.extend(_wrapped("ENTROPY", f"{stats['entropy_bits_per_byte']:.4f} bits/byte"))
        lines.extend(_wrapped("UTF-8", "yes" if stats["text_utf8"] else "no"))
        lines.extend(_wrapped("PRINTABLE", f"{stats['printable_ratio']:.1%}"))
        if primary:
            lines.extend(_wrapped("EVIDENCE", "; ".join(primary.evidence) or "None"))
            if primary.parameters:
                lines.extend(_wrapped("PARAMETERS", json.dumps(primary.parameters, ensure_ascii=False, sort_keys=True)))
            if primary.limitations:
                lines.extend(_wrapped("LIMITATIONS", "; ".join(primary.limitations)))

    lines.append("")
    lines.append(c("Confidence describes pattern fit, not cryptographic validity.", "33"))
    lines.append("ADIN does not execute input, contact a network, or decrypt unknown ciphertext.")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="adin",
        description="Offline-first encoding, cryptographic-format, hash-candidate, and binary inspector.",
        epilog="Examples: adin 'SGVsbG8=' | adin --file evidence.bin | cat input.txt | adin - | adin --json '48656c6c6f'",
    )
    parser.add_argument("input", nargs="?", help="literal input string, or '-' to read stdin")
    parser.add_argument("-f", "--file", metavar="PATH", help="read bytes from a file")
    parser.add_argument("--json", action="store_true", help="print a machine-readable JSON report")
    parser.add_argument("--verbose", action="store_true", help="show all candidates and technical parameters")
    parser.add_argument("--depth", type=int, default=3, help="maximum nested decode depth (0-10; default: 3)")
    parser.add_argument("--max-bytes", type=int, default=1_048_576, help="maximum input size in bytes (default: 1 MiB)")
    parser.add_argument("--version", action="version", version=f"ADIN {__version__}")
    return parser


def _read_input(args: argparse.Namespace, parser: argparse.ArgumentParser) -> tuple[bytes, str]:
    if args.file and args.input is not None:
        parser.error("provide either a literal input or --file, not both")
    if args.file:
        try:
            with open(args.file, "rb") as stream:
                data = stream.read(args.max_bytes + 1)
            return data, args.file
        except OSError as exc:
            parser.error(f"cannot read {args.file!r}: {exc}")
    if args.input == "-":
        return sys.stdin.buffer.read(args.max_bytes + 1), "stdin"
    if args.input is not None:
        return args.input.encode("utf-8"), "argument"
    if not sys.stdin.isatty():
        return sys.stdin.buffer.read(args.max_bytes + 1), "stdin"
    parser.error("provide INPUT, --file PATH, or pipe bytes to stdin")
    raise AssertionError("argparse.error always exits")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.max_bytes < 1:
        parser.error("--max-bytes must be at least 1")
    data, source = _read_input(args, parser)
    try:
        report = analyze(data, source=source, max_depth=args.depth, max_bytes=args.max_bytes)
    except ValueError as exc:
        parser.error(str(exc))
    if args.json:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(render_terminal(report, verbose=args.verbose, input_data=data))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
