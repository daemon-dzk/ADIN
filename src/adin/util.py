"""Small safe helpers shared by detectors."""
from __future__ import annotations

import math
import string
from collections import Counter


def printable_preview(data: bytes, limit: int = 180) -> str:
    """Return a bounded, escaped preview; never execute or interpret the data."""
    sample = data[:limit]
    try:
        text = sample.decode("utf-8")
        rendered = "".join(ch if ch.isprintable() or ch in "\n\r\t" else f"\\x{ord(ch):02x}" for ch in text)
    except UnicodeDecodeError:
        rendered = "".join(chr(b) if 32 <= b < 127 else f"\\x{b:02x}" for b in sample)
    if len(data) > limit:
        rendered += "…"
    return rendered


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = -sum((n / total) * math.log2(n / total) for n in counts.values())
    return 0.0 if entropy == 0 else entropy


def looks_like_text(data: bytes) -> bool:
    if not data:
        return True
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if not text:
        return True
    acceptable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
    return acceptable / len(text) >= 0.85


def english_word_score(text: str) -> float:
    """A conservative, deliberately tiny English signal for classical ciphers."""
    words = [w.strip(string.punctuation).lower() for w in text.split()]
    if not words:
        return 0.0
    common = {
        "the", "be", "to", "of", "and", "a", "in", "that", "have", "i", "it",
        "for", "not", "on", "with", "he", "as", "you", "do", "at", "this", "but",
        "his", "by", "from", "they", "we", "say", "her", "she", "or", "an", "will",
        "my", "one", "all", "would", "there", "their", "what", "so", "up", "out",
        "if", "about", "who", "get", "which", "go", "me", "hello", "world", "secret",
        "flag", "password", "message", "attack", "meet", "dawn", "test", "message",
    }
    hits = sum(1 for w in words if w in common)
    return hits / len(words)
