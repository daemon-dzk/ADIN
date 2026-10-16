"""Deterministic encodings and classical-cipher checks."""
from __future__ import annotations

import base64
import binascii
import html
import quopri
import re
import urllib.parse
from typing import Callable

from ..models import Detection
from ..util import english_word_score, looks_like_text, printable_preview

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9", ".-.-.-": ".", "--..--": ",", "..--..": "?",
    "-.-.--": "!", "-....-": "-", "-..-.": "/", ".--.-.": "@",
}


def _text(data: bytes) -> str | None:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _det(name: str, category: str, score: float, description: str, evidence: list[str], decoded: bytes | None = None, limitations: list[str] | None = None, parameters: dict | None = None, detector: str = "encoding") -> Detection:
    preview = printable_preview(decoded) if decoded is not None else None
    return Detection(name=name, category=category, score=score, description=description,
                     evidence=evidence, limitations=limitations or [], parameters=parameters or {},
                     decoded_preview=preview, decoded_bytes=decoded, detector=detector)


def _b58decode(value: str) -> bytes:
    n = 0
    for char in value:
        n = n * 58 + _B58.index(char)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    zeroes = len(value) - len(value.lstrip("1"))
    return b"\x00" * zeroes + body


def _b58check(value: str) -> bytes:
    if not value or any(c not in _B58 for c in value):
        raise ValueError("not base58 alphabet")
    out = _b58decode(value)
    if len(value) < 8:
        raise ValueError("too short for useful base58 signal")
    return out


_B45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
def _b45decode(value: str) -> bytes:
    if not value or any(c not in _B45 for c in value) or len(value) % 3 == 1:
        raise ValueError("invalid Base45 input")
    out = bytearray()
    i = 0
    while i < len(value):
        remaining = len(value) - i
        if remaining >= 3:
            number = _B45.index(value[i]) + 45 * _B45.index(value[i+1]) + 2025 * _B45.index(value[i+2])
            if number > 65535:
                raise ValueError("Base45 pair exceeds two-byte range")
            out.extend((number // 256, number % 256))
            i += 3
        else:
            number = _B45.index(value[i]) + 45 * _B45.index(value[i+1])
            if number > 255:
                raise ValueError("Base45 final byte exceeds byte range")
            out.append(number)
            i += 2
    return bytes(out)


def _b45encode(data: bytes) -> str:
    out: list[str] = []
    i = 0
    while i < len(data):
        if i + 1 < len(data):
            number = data[i] * 256 + data[i+1]
            out.extend((_B45[number % 45], _B45[(number // 45) % 45], _B45[number // 2025]))
            i += 2
        else:
            number = data[i]
            out.extend((_B45[number % 45], _B45[number // 45]))
            i += 1
    return "".join(out)


_B91 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"'

def _b91decode(value: str) -> bytes:
    bit_buffer = 0
    bit_count = 0
    pending = -1
    out = bytearray()
    for char in value:
        pos = _B91.find(char)
        if pos < 0:
            raise ValueError("invalid basE91 alphabet")
        if pending < 0:
            pending = pos
            continue
        number = pending + pos * 91
        pending = -1
        bit_buffer |= number << bit_count
        bit_count += 13 if (number & 8191) > 88 else 14
        while bit_count > 7:
            out.append(bit_buffer & 255)
            bit_buffer >>= 8
            bit_count -= 8
    if pending >= 0:
        out.append((bit_buffer | (pending << bit_count)) & 255)
    return bytes(out)


def _b91encode(data: bytes) -> str:
    bit_buffer = 0
    bit_count = 0
    out: list[str] = []
    for byte in data:
        bit_buffer |= byte << bit_count
        bit_count += 8
        if bit_count > 13:
            number = bit_buffer & 8191
            if number > 88:
                bit_buffer >>= 13
                bit_count -= 13
            else:
                number = bit_buffer & 16383
                bit_buffer >>= 14
                bit_count -= 14
            out.extend((_B91[number % 91], _B91[number // 91]))
    if bit_count:
        if bit_count > 7 or bit_buffer > 90:
            out.extend((_B91[bit_buffer % 91], _B91[bit_buffer // 91]))
        else:
            out.append(_B91[bit_buffer])
    return "".join(out)


def _decode_unpadded_b64(s: str, urlsafe: bool = False) -> bytes:
    raw = s.encode("ascii")
    raw += b"=" * ((-len(raw)) % 4)
    return base64.urlsafe_b64decode(raw) if urlsafe else base64.b64decode(raw, validate=True)


def detect_encodings(data: bytes) -> list[Detection]:
    found: list[Detection] = []
    s = _text(data)
    if s is None or not s:
        return found
    stripped = s.strip()
    if not stripped:
        return found

    # Explicit 0x-prefixed hexadecimal.
    compact_input = re.sub(r"\s+", "", stripped)
    prefixed = re.fullmatch(r"(?:0x)([0-9a-fA-F]+)", compact_input, re.IGNORECASE)
    if prefixed and len(prefixed.group(1)) >= 2 and len(prefixed.group(1)) % 2 == 0:
        try:
            dec = bytes.fromhex(prefixed.group(1))
            found.append(_det("0x-prefixed hexadecimal", "encoding", 0.98,
                "A 0x prefix explicitly indicates a hexadecimal byte or integer representation.",
                ["Input begins with 0x and the remaining even-length characters are hexadecimal."], dec,
                ["A hexadecimal number is not necessarily encrypted or encoded application data."], {"hex_digits": len(prefixed.group(1))}))
        except ValueError:
            pass

    # Hexadecimal is unambiguous only when a reasonably sized, even-length alphabet matches.
    compact = re.sub(r"\s+", "", stripped)
    if len(compact) >= 4 and len(compact) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", compact):
        try:
            decoded = bytes.fromhex(compact)
            score = 0.96 if len(compact) >= 8 else 0.72
            found.append(_det("Hexadecimal (Base16-like)", "encoding", score,
                "Hexadecimal represents each byte using two hexadecimal digits.",
                ["Only hexadecimal characters were present.", "The number of hexadecimal digits was even."], decoded,
                ["A hex-looking string can also be a number, identifier, or digest; decoded bytes do not prove intent."],
                {"hex_digits": len(compact), "whitespace_ignored": compact != stripped}))
        except ValueError:
            pass

    # Strict Base64 standard / URL-safe variants. Require recognizable size/padding to avoid weak guesses.
    if len(stripped) >= 4 and re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", stripped) and len(stripped.rstrip("=")) % 4 != 1:
        try:
            dec = _decode_unpadded_b64(stripped, False)
            canonical = base64.b64encode(dec).decode("ascii").rstrip("=")
            normalized = stripped.rstrip("=")
            if canonical == normalized and (len(stripped) >= 8 or "=" in stripped):
                hex_digest_shaped = len(stripped) in (32, 40, 56, 64, 96, 128) and bool(re.fullmatch(r"[0-9a-fA-F]+", stripped))
                score = (0.57 if hex_digest_shaped else (0.95 if "=" in stripped else 0.82 if len(stripped) >= 12 else 0.78))
                limitations = ["Base64 is encoding, not encryption. Any claimed underlying algorithm must be identified separately."]
                if "=" not in stripped:
                    limitations.append("Unpadded Base64 can overlap with ordinary text made only of Base64-alphabet characters.")
                if hex_digest_shaped:
                    limitations.append("This string is also hexadecimal and has a common digest length, so Base64 is an ambiguous interpretation.")
                found.append(_det("Base64", "encoding", score,
                    "Base64 encodes arbitrary bytes as ASCII text using a 64-symbol alphabet.",
                    ["Input matches the Base64 alphabet and decodes successfully.", "Re-encoding the decoded bytes reproduces the normalized input."], dec,
                    limitations,
                    {"input_characters": len(stripped), "padding_present": "=" in stripped}))
        except (binascii.Error, ValueError):
            pass

    if len(stripped) >= 8 and re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", stripped) and ("-" in stripped or "_" in stripped):
        try:
            dec = _decode_unpadded_b64(stripped, True)
            canonical = base64.urlsafe_b64encode(dec).decode("ascii").rstrip("=")
            if canonical == stripped.rstrip("="):
                url_score = 0.95 if "=" in stripped else (0.84 if "-" in stripped else 0.78)
                url_limits = ["This only identifies the representation, not the purpose or original content."]
                if "=" not in stripped:
                    url_limits.append("Unpadded Base64URL can overlap with ordinary identifiers that contain underscores or hyphens.")
                found.append(_det("Base64 URL-safe", "encoding", url_score,
                    "URL-safe Base64 replaces + and / with - and _ for safer use in URLs and tokens.",
                    ["The input uses URL-safe Base64 alphabet characters.", "Decoded bytes round-trip to the normalized input."], dec,
                    url_limits, {"padding_present": "=" in stripped}))
        except (binascii.Error, ValueError):
            pass

    hex_digest_shaped = len(stripped) in (32, 40, 56, 64, 96, 128) and bool(re.fullmatch(r"[0-9a-fA-F]+", stripped))
    if not hex_digest_shaped and len(stripped) >= 8 and re.fullmatch(r"[A-Z2-7]+=*", stripped.upper()) and len(stripped.rstrip("=")) % 8 not in (1, 3, 6):
        try:
            normalized_b32 = stripped.upper().rstrip("=")
            candidate = stripped.upper().encode("ascii")
            candidate += b"=" * ((-len(candidate)) % 8)
            dec = base64.b32decode(candidate, casefold=True)
            canonical_b32 = base64.b32encode(dec).decode("ascii").rstrip("=")
            if canonical_b32 == normalized_b32:
                if "=" in stripped:
                    b32_score = 0.92
                elif looks_like_text(dec):
                    b32_score = 0.88
                else:
                    b32_score = 0.66
                found.append(_det("Base32", "encoding", b32_score,
                    "Base32 represents data using a restricted alphabet of letters A–Z and digits 2–7.",
                    ["Input fits the Base32 alphabet, decodes successfully, and round-trips canonically."], dec,
                    ["Base32-compatible uppercase words can occur naturally; decoded-content plausibility is only supporting evidence."], {"padding_present": "=" in stripped}))
        except (binascii.Error, ValueError):
            pass

    if len(stripped) >= 10 and re.fullmatch(r"[!-u]+", stripped):
        for label, decoder in (("Base85 (RFC 1924 alphabet)", base64.b85decode), ("Ascii85", base64.a85decode)):
            try:
                dec = decoder(stripped.encode("ascii"))
                if dec and (len(stripped) >= 12 or any(c in stripped for c in "<>z")):
                    found.append(_det(label, "encoding", 0.61,
                        "Base85 encodes binary data into a compact printable-character representation.",
                        ["A Base85-family decoder accepted the input."], dec,
                        ["Base85 alphabets overlap with ordinary punctuation; treat this as a candidate unless context confirms it."], {}, detector="encoding"))
            except (ValueError, binascii.Error):
                pass

    if 8 <= len(stripped) <= 512 and all(c in _B58 for c in stripped):
        try:
            dec = _b58check(stripped)
            found.append(_det("Base58 (Bitcoin alphabet)", "encoding", 0.72,
                "Base58 encodes byte sequences using an alphabet designed to avoid visually ambiguous characters.",
                ["Every character belongs to the Bitcoin Base58 alphabet.", "Input is long enough to be a plausible encoded payload."], dec,
                ["Base58 has no universal marker; many identifiers and random strings share this alphabet."], {"input_characters": len(stripped)}))
        except (ValueError, OverflowError):
            pass
        try:
            import hashlib
            decoded58 = _b58check(stripped)
            if len(decoded58) >= 5:
                payload, checksum = decoded58[:-4], decoded58[-4:]
                expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
                if checksum == expected:
                    found.append(_det("Base58Check (checksum verified)", "encoding", 0.99,
                        "Base58Check combines Base58 representation with a four-byte double-SHA-256 checksum.",
                        ["Decoded bytes contain a checksum matching the first four bytes of double-SHA-256(payload)."], payload,
                        ["A valid checksum detects accidental corruption but does not prove source authenticity."], {"payload_length_bytes": len(payload), "checksum": checksum.hex()}))
        except (ValueError, OverflowError):
            pass

    # Base45 is used by QR and compact transport formats; canonical round-trip limits false positives.
    if len(stripped) >= 6 and all(c in _B45 for c in stripped):
        try:
            dec = _b45decode(stripped)
            if _b45encode(dec) == stripped:
                found.append(_det("Base45", "encoding", 0.85,
                    "Base45 represents binary data with a 45-character alphabet and is used in compact QR-oriented formats.",
                    ["Input uses the Base45 alphabet.", "Decoding and re-encoding produced an exact round trip."], dec,
                    ["Other text may use the same restricted alphabet; context still matters."], {"input_characters": len(stripped)}))
        except (ValueError, IndexError):
            pass

    # basE91 has a large printable alphabet; require canonical round-trip to reduce false positives.
    if len(stripped) >= 12 and all(c in _B91 for c in stripped):
        try:
            dec = _b91decode(stripped)
            if dec and _b91encode(dec) == stripped:
                found.append(_det("basE91", "encoding", 0.84,
                    "basE91 is a compact binary-to-text encoding that uses a 91-character alphabet.",
                    ["Input uses the basE91 alphabet.", "Decoding and re-encoding produced an exact round trip."], dec,
                    ["As with other printable encodings, a format match identifies representation, not the original application purpose."], {"input_characters": len(stripped)}))
        except (ValueError, OverflowError):
            pass

    # Quoted-printable is often used in MIME email bodies.
    if re.search(r"=[0-9A-Fa-f]{2}|=\r?\n", stripped):
        dec = quopri.decodestring(stripped.encode("utf-8"))
        if dec != stripped.encode("utf-8"):
            found.append(_det("Quoted-printable (MIME)", "encoding", 0.92,
                "Quoted-printable represents non-printable bytes using =HH escapes and can fold lines with a trailing equals sign.",
                ["Recognized quoted-printable byte escapes or soft line breaks were present."], dec,
                ["This encoding is common in email; decoding is not equivalent to validating or sanitizing message content."], {}))

    # Explicit Unicode code point notation, for example U+0048 U+0069.
    if re.fullmatch(r"(?:U\+[0-9A-Fa-f]{2,6})(?:[ ,]+U\+[0-9A-Fa-f]{2,6})+", stripped):
        try:
            points = re.findall(r"U\+([0-9A-Fa-f]{2,6})", stripped)
            dec_text = "".join(chr(int(point, 16)) for point in points)
            found.append(_det("Unicode code point notation", "encoding", 0.98,
                "U+ notation names Unicode code points rather than encrypting text.",
                [f"Recognized {len(points)} Unicode code point tokens."], dec_text.encode("utf-8"),
                ["Some code points are non-printable or can affect text display."], {"code_points": len(points)}))
        except (ValueError, OverflowError):
            pass

    # Numeric byte values separated by spaces or commas (decimal / octal).
    for base, label, pattern in ((10, "Decimal byte values", r"(?:[0-9]{1,3})(?:[ ,]+[0-9]{1,3}){2,}"),
                                 (8, "Octal byte values", r"(?:[0-7]{1,3})(?:[ ,]+[0-7]{1,3}){2,}")):
        if re.fullmatch(pattern, stripped):
            try:
                tokens = re.split(r"[ ,]+", stripped)
                values = [int(token, base) for token in tokens]
                if all(0 <= value <= 255 for value in values):
                    dec = bytes(values)
                    found.append(_det(label, "encoding", 0.79,
                        f"The input resembles {label.lower()} where each number represents one byte.",
                        [f"Parsed {len(values)} values, all within the byte range 0–255."], dec,
                        ["Numeric sequences can also be ordinary data or lists of numbers; separators and context matter."], {"base": base, "values": len(values)}))
            except (ValueError, OverflowError):
                pass

    # Percent/URL encoding.
    if re.search(r"%[0-9A-Fa-f]{2}", stripped):
        try:
            dec = urllib.parse.unquote_to_bytes(stripped)
            if dec != data:
                found.append(_det("Percent / URL encoding", "encoding", 0.97,
                    "Percent encoding represents bytes as % followed by two hexadecimal digits.",
                    ["One or more valid %HH byte escapes were present."], dec,
                    ["Reserved-character decoding rules depend on whether the source was a URL path, query, or form."], {}))
        except (ValueError, UnicodeError):
            pass

    # HTML entities (only when an entity changed the input).
    unescaped = html.unescape(stripped)
    if unescaped != stripped and re.search(r"&(?:#\d+|#x[0-9A-Fa-f]+|[A-Za-z][A-Za-z0-9]+);", stripped):
        found.append(_det("HTML character references", "encoding", 0.95,
            "HTML entities represent characters using named or numeric references.",
            ["Recognized HTML character references changed the input when decoded."], unescaped.encode("utf-8"),
            ["HTML unescaping is context-sensitive; this does not sanitize HTML or make it safe to render."], {}))

    # Common backslash escaped strings.
    if re.search(r"\\(?:u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|x[0-9a-fA-F]{2}|n|r|t|\\)", stripped):
        try:
            decoded_text = bytes(stripped, "utf-8").decode("unicode_escape")
            if decoded_text != stripped:
                found.append(_det("Backslash / Unicode escapes", "encoding", 0.87,
                    "String-literal escape sequences represent characters or byte values using backslashes.",
                    ["Recognized escape sequences are present and decode to a different string."], decoded_text.encode("utf-8"),
                    ["Unicode escape interpretation can vary by programming language and literal type."], {}))
        except (UnicodeDecodeError, UnicodeEncodeError, ValueError):
            pass

    # Binary groups, permitting spaces between octets.
    groups = stripped.split()
    if len(groups) >= 1 and all(len(g) == 8 and set(g) <= {"0", "1"} for g in groups) and len(groups) >= 2:
        try:
            dec = bytes(int(g, 2) for g in groups)
            found.append(_det("Binary octets", "encoding", 0.98,
                "Each group is an 8-bit binary representation of one byte.",
                ["Input consists entirely of 8-bit binary groups."], dec,
                ["Whitespace-separated binary groups are a representation convention rather than a cryptographic algorithm."], {"octets": len(groups)}))
        except ValueError:
            pass
    elif len(compact) >= 16 and len(compact) % 8 == 0 and set(compact) <= {"0", "1"}:
        dec = bytes(int(compact[i:i+8], 2) for i in range(0, len(compact), 8))
        found.append(_det("Binary octets", "encoding", 0.97,
            "The input can be split into consecutive 8-bit binary bytes.",
            ["Input contains only 0 and 1 and its length is divisible by eight."], dec,
            ["Binary-looking data can be intentionally written as a bit string; this does not indicate encryption."], {"octets": len(dec)}))

    # Morse requires word separators and avoids interpreting one dot as Morse.
    if len(stripped) >= 5 and re.fullmatch(r"[.\-/| ]+", stripped) and any(c in stripped for c in "-/| "):
        try:
            words = re.split(r"\s*[/|]\s*", stripped)
            output_words = []
            valid = True
            for word in words:
                tokens = word.split()
                if not tokens:
                    continue
                letters = []
                for token in tokens:
                    if token not in _MORSE:
                        valid = False
                        break
                    letters.append(_MORSE[token])
                output_words.append("".join(letters))
            if valid and output_words:
                dec = " ".join(output_words).encode()
                found.append(_det("Morse code", "encoding", 0.80,
                    "Morse code represents letters and digits with sequences of dots and dashes.",
                    ["All separated code groups map to the built-in alphanumeric Morse table."], dec,
                    ["Morse spacing conventions vary; punctuation support is intentionally limited."], {}))
        except Exception:
            pass

    # Classical ciphers are inherently ambiguous; only surface candidates with a useful signal.
    letters = sum(c.isalpha() and c.isascii() for c in stripped)
    if letters >= 4 and len(stripped) <= 20000:
        original_score = english_word_score(stripped)
        candidates: list[tuple[float, str, str, str]] = []
        atbash = "".join(chr(ord('Z') - (ord(c.upper()) - ord('A'))) if c.isupper() and c.isascii() and c.isalpha() else chr(ord('z') - (ord(c) - ord('a'))) if c.islower() and c.isascii() and c.isalpha() else c for c in stripped)
        a_score = english_word_score(atbash)
        if a_score >= 0.35 and a_score > original_score + 0.15:
            candidates.append((a_score, "Atbash (candidate)", atbash, "Atbash maps each letter to its reverse in the alphabet."))
        for shift in range(1, 26):
            out = []
            for c in stripped:
                if "a" <= c <= "z": out.append(chr((ord(c)-97-shift) % 26 + 97))
                elif "A" <= c <= "Z": out.append(chr((ord(c)-65-shift) % 26 + 65))
                else: out.append(c)
            decoded_text = "".join(out)
            score = english_word_score(decoded_text)
            if score >= 0.35 and score > original_score + 0.15:
                cipher_name = "ROT13 / Caesar shift 13 (candidate)" if shift == 13 else f"Caesar shift {shift} (candidate)"
                candidates.append((score, cipher_name, decoded_text, "A Caesar cipher shifts alphabet letters by a fixed amount."))
        # Keep the strongest classical candidates only.
        for score, name, decoded_text, desc in sorted(candidates, reverse=True)[:2]:
            found.append(_det(name, "classical_cipher_candidate", min(0.72, 0.48 + score * 0.35), desc,
                [f"A small English-word heuristic score was {score:.2f} after transformation."], decoded_text.encode("utf-8"),
                ["Classical-cipher identification is heuristic and can be wrong, especially for short text or non-English plaintext."], {"heuristic_english_word_score": round(score, 3)}, detector="classical"))

    return found
