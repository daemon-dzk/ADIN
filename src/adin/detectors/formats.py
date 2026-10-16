"""Recognize common structured cryptographic formats, hashes, and file signatures."""
from __future__ import annotations

import base64
import binascii
import re

from ..models import Detection
from ..util import printable_preview


def _d(name: str, category: str, score: float, description: str, evidence: list[str], *, limitations: list[str] | None = None, parameters: dict | None = None, decoded: bytes | None = None, detector: str = "format") -> Detection:
    return Detection(name=name, category=category, score=score, description=description,
                     evidence=evidence, limitations=limitations or [], parameters=parameters or {},
                     decoded_preview=printable_preview(decoded) if decoded is not None else None,
                     decoded_bytes=decoded, detector=detector)


def _b64url(part: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]*", part):
        raise ValueError("invalid base64url alphabet")
    raw = part.encode("ascii") + b"=" * ((-len(part)) % 4)
    return base64.urlsafe_b64decode(raw)


def detect_crypto_formats(data: bytes) -> list[Detection]:
    found: list[Detection] = []
    try:
        s = data.decode("utf-8").strip()
    except UnicodeDecodeError:
        s = ""

    if s:
        # Compact JWT/JWS and JWE. Do not call a signed token encrypted.
        parts = s.split(".")
        if len(parts) == 3 and all(parts):
            try:
                header_bytes = _b64url(parts[0])
                header_text = header_bytes.decode("utf-8")
                import json
                header = json.loads(header_text)
                if isinstance(header, dict) and isinstance(header.get("alg"), str):
                    payload = _b64url(parts[1])
                    try:
                        payload_text = payload.decode("utf-8")
                    except UnicodeDecodeError:
                        payload_text = None
                    payload_is_json = False
                    if payload_text is not None:
                        try:
                            json.loads(payload_text)
                            payload_is_json = True
                        except (ValueError, TypeError):
                            pass
                    found.append(_d("Compact JWS / signed JWT candidate", "signed_token", 0.99,
                        "A three-segment compact token with a JSON header resembles JWS, commonly used by signed JWTs.",
                        ["There are exactly three non-empty dot-separated segments.", "The first segment decodes to a JSON object with an alg field."],
                        limitations=["A matching structure is not proof of signature validity. The signature was not verified; alg=none and non-JWT lookalikes require special care."],
                        parameters={"header": header, "payload_is_json": payload_is_json}, decoded=payload if payload_text is not None else None))
            except (ValueError, UnicodeDecodeError, binascii.Error):
                pass
        elif len(parts) == 5 and all(parts):
            try:
                header = __import__("json").loads(_b64url(parts[0]).decode("utf-8"))
                if isinstance(header, dict) and "enc" in header:
                    found.append(_d("Compact JWE candidate", "encrypted_token", 0.99,
                        "A five-segment compact token with a JSON header resembles JWE, a standard format for encrypted content.",
                        ["There are exactly five non-empty dot-separated segments.", "The first segment decodes to a JSON object with an enc parameter."],
                        limitations=["ADIN does not decrypt the token or validate authentication tags; key material and algorithm policy are required."],
                        parameters={"header": header, "segment_lengths": [len(p) for p in parts]}))
            except (ValueError, UnicodeDecodeError, binascii.Error):
                pass

        # PEM / OpenSSH / PGP armor.
        if s.startswith("-----BEGIN PGP "):
            found.append(_d("PGP armored data", "cryptographic_container", 0.99,
                "OpenPGP ASCII armor is a textual envelope for keys, signatures, or messages.",
                ["Input begins with a PGP armor marker."], limitations=["Armor label alone does not establish the message contents or signature validity."], parameters={"header": s.splitlines()[0]}))
        else:
            pem = re.search(r"-----BEGIN ([A-Z0-9 ][A-Z0-9 _-]*)-----", s)
            if pem:
                label = pem.group(1).strip()
                found.append(_d(f"PEM armor ({label})", "cryptographic_container", 0.99,
                    "PEM uses BEGIN/END labels around Base64-encoded cryptographic or certificate data.",
                    [f"Recognized PEM-style begin marker: {label}."],
                    limitations=["The label identifies the container type, not whether the key/certificate is valid or trusted."], parameters={"label": label}))
            elif s.startswith(("ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-", "sk-ssh-ed25519@openssh.com ")):
                fields = s.split()
                found.append(_d("OpenSSH public-key line", "public_key", 0.99,
                    "OpenSSH public keys use a textual algorithm label followed by Base64-encoded key data.",
                    [f"Recognized public-key type field: {fields[0]}.", "The line begins with a known OpenSSH public-key identifier."],
                    limitations=["The key's authenticity, ownership, and cryptographic validity are not verified by this format check."], parameters={"key_type": fields[0], "comment_present": len(fields) > 2}))

        # Password-hash encodings with algorithm-identifying prefix/structure.
        if re.match(r"^\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}$", s):
            found.append(_d("bcrypt password hash", "password_hash", 0.99,
                "bcrypt is a salted, adaptive password-hashing scheme with a cost parameter.",
                ["Input matches the $2a$, $2b$, or $2y$ modular-crypt structure."], limitations=["This is not reversible encryption. No cracking or password guessing is performed."], parameters={"variant": s[1:3], "cost": int(s[4:6])}))
        if s.startswith("$argon2i$") or s.startswith("$argon2id$") or s.startswith("$argon2d$"):
            found.append(_d("Argon2 password hash", "password_hash", 0.99,
                "Argon2 is a memory-hard password-hashing function; variants include Argon2i, Argon2d, and Argon2id.",
                ["Input begins with a recognized Argon2 modular-crypt identifier."], limitations=["Parameters may be parsed as metadata, but password verification requires a dedicated implementation and supplied candidate password."], parameters={"variant": s.split("$")[1] if len(s.split("$")) > 1 else None}))
        if re.match(r"^(pbkdf2_(?:sha1|sha256|sha512)|pbkdf2-sha256|sha256crypt|sha512crypt)\$", s, re.I):
            found.append(_d("PBKDF2 / modular password-hash format candidate", "password_hash", 0.94,
                "The string resembles a common serialized password hash or key-derivation result format.",
                ["Recognized algorithm-like prefix and delimiter pattern."], limitations=["Serialized formats differ across implementations; the prefix may not uniquely identify all parameters."], parameters={"prefix": s.split("$")[0]}))

        if re.match(r"^\$(?:1|5|6|y)\$", s):
            fields = s.split("$")
            code = fields[1] if len(fields) > 1 else ""
            salt = encoded_hash = params = None
            if code == "1" and len(fields) == 4:
                salt, encoded_hash = fields[2], fields[3]
            elif code in ("5", "6") and len(fields) in (4, 5):
                if len(fields) == 5 and fields[2].startswith("rounds=") and fields[2][7:].isdigit():
                    params, salt, encoded_hash = fields[2], fields[3], fields[4]
                elif len(fields) == 4:
                    salt, encoded_hash = fields[2], fields[3]
            elif code == "y" and len(fields) == 5:
                params, salt, encoded_hash = fields[2], fields[3], fields[4]
            if salt and encoded_hash:
                scheme = {"1": "MD5-crypt", "5": "SHA-256-crypt", "6": "SHA-512-crypt", "y": "yescrypt"}[code]
                found.append(_d(f"Unix modular password hash ({scheme})", "password_hash", 0.98,
                    f"The value matches the common modular-crypt serialization used for {scheme} password hashes.",
                    [f"Recognized modular-crypt identifier ${code}$ and salt/hash field separators."],
                    limitations=["This format match does not verify the digest and is not reversible encryption."], parameters={"scheme": scheme, "parameters": params, "salt_length": len(salt), "encoded_hash_length": len(encoded_hash)}))

        if re.match(r"^(scrypt:\d+:\d+:\d+\$|\$scrypt\$)", s):
            found.append(_d("scrypt password-hash serialization candidate", "password_hash", 0.96,
                "The prefix resembles a serialized scrypt password hash / key-derivation result.",
                ["Recognized scrypt-specific format marker."], limitations=["Implementations serialize scrypt parameters differently; this is a format identification, not verification."], parameters={"prefix": s.split("$")[0]}))

        if re.match(r"^(?:\$P\$|\$H\$)", s):
            found.append(_d("phpass password hash", "password_hash", 0.95,
                "The value begins with a common phpass portable password-hash marker.",
                ["Recognized $P$ or $H$ prefix."], limitations=["Format marker recognition does not verify the digest or recover a password."], parameters={"prefix": s[:3]}))

        if s.startswith("SHA256:") and re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", s):
            found.append(_d("OpenSSH SHA-256 fingerprint", "key_fingerprint", 0.99,
                "OpenSSH commonly displays SHA-256 key fingerprints using a SHA256: prefix and Base64 digest.",
                ["Input matches SHA256: plus 43 Base64 alphabet characters."], limitations=["A string matching this format is not linked to a specific SSH key unless compared with a trusted source."], parameters={"digest_encoding": "Base64"}))

        # Fernet has a well-known URL-safe Base64 token representation and version byte 0x80.
        if len(s) >= 80 and re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", s):
            try:
                raw = _b64url(s.rstrip("="))
                if len(raw) >= 57 and raw[0] == 0x80:
                    found.append(_d("Fernet token candidate", "encrypted_token", 0.96,
                        "Fernet is a versioned authenticated-encryption token format from the Python cryptography ecosystem.",
                        ["URL-safe Base64 decoding yielded a 0x80 version byte and a plausible minimum token length."],
                        limitations=["Token authenticity and ciphertext contents cannot be confirmed without the correct key."], parameters={"decoded_length_bytes": len(raw), "version_byte": raw[0]}))
            except (ValueError, binascii.Error):
                pass

    # OpenSSL enc salted header can appear as raw bytes or inside base64-decoded content.
    if data.startswith(b"Salted__") and len(data) >= 16:
        found.append(_d("OpenSSL salted-data header", "encrypted_data_container", 0.98,
            "The bytes begin with OpenSSL's legacy Salted__ marker followed by an eight-byte salt in common enc formats.",
            ["Raw data begins with the literal Salted__ marker.", "The input is long enough to contain the marker and salt."],
            limitations=["This marker does not by itself identify the cipher, key derivation function, or password; modern OpenSSL enc options can use other formats."], parameters={"salt_hex": data[8:16].hex(), "payload_length_bytes": len(data)-16}))

    # Common binary/file signatures. This is a signature match, not a cryptographic claim.
    signatures = [
        (b"\x1f\x8b", "GZIP compressed stream", "compression", "GZIP uses a recognizable two-byte magic signature."),
        (b"BZh", "BZIP2 compressed stream", "compression", "BZIP2 streams begin with BZh and a block-size digit."),
        (b"\xfd7zXZ\x00", "XZ compressed stream", "compression", "XZ uses a standard six-byte magic signature."),
        (b"PK\x03\x04", "ZIP archive", "archive", "ZIP local file headers begin with PK\\x03\\x04."),
        (b"PK\x05\x06", "ZIP empty/end-of-central-directory marker", "archive", "This is a ZIP end-of-central-directory marker."),
        (b"\x7fELF", "ELF executable/object", "binary_format", "ELF is the standard executable and object format on many Unix-like systems."),
        (b"MZ", "DOS/Windows PE-family candidate", "binary_format", "MZ is the DOS header signature commonly present in Windows PE files."),
        (b"\x89PNG\r\n\x1a\n", "PNG image", "binary_format", "PNG uses a standard eight-byte signature."),
        (b"GIF87a", "GIF image", "binary_format", "GIF87a is a standard GIF signature."),
        (b"GIF89a", "GIF image", "binary_format", "GIF89a is a standard GIF signature."),
        (b"\xff\xd8\xff", "JPEG image", "binary_format", "JPEG files commonly begin with FF D8 FF."),
        (b"%PDF-", "PDF document", "binary_format", "PDF files commonly begin with %PDF-."),
        (b"SQLite format 3\x00", "SQLite database", "binary_format", "SQLite databases use this exact 16-byte header."),
        (b"Rar!\x1a\x07", "RAR archive", "archive", "RAR files use a recognizable signature."),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", "archive", "7z archives use a standard six-byte signature."),
    ]
    for sig, name, category, desc in signatures:
        if data.startswith(sig):
            found.append(_d(name, category, 0.99, desc, [f"Input begins with recognized signature {sig[:8].hex()}."] , parameters={"signature_hex": sig.hex(), "input_length_bytes": len(data)}, detector="signature"))

    # A small strict DER length check can surface ASN.1 containers commonly used for keys/certificates.
    if len(data) >= 4 and data[0] == 0x30:
        first_len = data[1]
        header_len = 2
        declared_len = None
        if first_len < 0x80:
            declared_len = first_len
        else:
            length_octets = first_len & 0x7F
            if 1 <= length_octets <= 4 and len(data) >= 2 + length_octets:
                declared_len = int.from_bytes(data[2:2+length_octets], "big")
                header_len += length_octets
        if declared_len is not None and declared_len > 0 and declared_len <= len(data) - header_len:
            exact = declared_len == len(data) - header_len
            found.append(_d("ASN.1 DER SEQUENCE candidate", "binary_format", 0.88 if exact else 0.73,
                "The bytes begin with an ASN.1 SEQUENCE tag and a length field consistent with a DER-encoded object.",
                ["Recognized tag 0x30.", f"Length field declares {declared_len} content bytes.", "Declared length fits within the supplied input."],
                limitations=["DER is used by many unrelated data structures; this check does not prove the object is a certificate, key, or valid ASN.1 tree."], parameters={"declared_content_length": declared_len, "exact_length_match": exact}, detector="asn1"))

    # Hash digest candidates: intentionally ambiguous unless a structured prefix identifies a scheme.
    if s and len(s) in (32, 40, 56, 64, 96, 128) and re.fullmatch(r"[0-9a-fA-F]+", s):
        candidates = {
            32: ["MD5", "NTLM"],
            40: ["SHA-1", "RIPEMD-160"],
            56: ["SHA-224"],
            64: ["SHA-256", "SHA3-256", "BLAKE2s-256"],
            96: ["SHA-384", "SHA3-384"],
            128: ["SHA-512", "SHA3-512", "BLAKE2b-512"],
        }[len(s)]
        found.append(_d(f"Hex digest-length candidate ({len(s)} characters)", "possible_hash", 0.67,
            "The input's hexadecimal length is compatible with one or more common hash digests.",
            [f"Input is hexadecimal and has {len(s)} characters ({len(s)//2} bytes)."],
            limitations=["Length and alphabet cannot prove the value is a hash or distinguish algorithms with the same digest length."], parameters={"candidates": candidates, "hex_characters": len(s)}, detector="hash"))
    return found
