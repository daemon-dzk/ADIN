import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest

from adin.pipeline import analyze
from adin.cli import main, render_terminal


def all_names(report):
    return [d.name for layer in report.layers for d in layer.detections]


def test_base64_decodes_and_reports_encoding_not_encryption():
    report = analyze(b"SGVsbG8=", max_depth=2)
    names = all_names(report)
    assert "Base64" in names
    assert len(report.layers) >= 2
    first = report.layers[0]
    match = next(d for d in first.detections if d.name == "Base64")
    assert match.decoded_bytes == b"Hello"
    assert "encoding" == match.category


def test_hex_detection():
    report = analyze(b"48656c6c6f")
    match = next(d for d in report.layers[0].detections if d.name.startswith("Hexadecimal"))
    assert match.decoded_bytes == b"Hello"


def test_digest_length_is_marked_ambiguous_and_not_followed_as_hex():
    value = b"a" * 64
    report = analyze(value)
    names = all_names(report)
    assert any("digest-length candidate" in name for name in names)
    assert len(report.layers) == 1
    match = next(d for d in report.layers[0].detections if "digest-length candidate" in d.name)
    assert "cannot prove" in " ".join(match.limitations)


def test_jwt_like_structure_is_recognized():
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(b'{"sub":"123","name":"Ada"}').decode().rstrip("=")
    signature = base64.urlsafe_b64encode(b"demo-signature").decode().rstrip("=")
    report = analyze(f"{header}.{payload}.{signature}".encode())
    match = next(d for d in report.layers[0].detections if "JWS" in d.name)
    assert match.parameters["header"]["alg"] == "HS256"
    assert any("not verified" in item for item in match.limitations)


def test_pem_header_detection():
    report = analyze(b"-----BEGIN PUBLIC KEY-----\nYWJj\n-----END PUBLIC KEY-----")
    assert any("PEM armor" in n for n in all_names(report))


def test_binary_signature_detected():
    report = analyze(b"\x89PNG\r\n\x1a\n" + b"x" * 20)
    assert "PNG image" in all_names(report)


def test_nested_encoding():
    inner = base64.b64encode(b"hello").decode()
    outer = base64.b64encode(inner.encode()).decode()
    report = analyze(outer.encode(), max_depth=3)
    assert len(report.layers) >= 3
    assert report.layers[2].byte_length == len(b"hello")


def test_empty_input_has_warning():
    report = analyze(b"")
    assert report.warnings


def test_max_bytes_guard():
    with pytest.raises(ValueError, match="configured limit"):
        analyze(b"12345", max_bytes=4)


def test_json_output_serializes_without_private_decoded_bytes(capsys):
    assert main(["--json", "SGVsbG8="]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["tool"] == "ADIN"
    rendered = json.dumps(output)
    assert '"decoded_bytes"' not in rendered


def test_terminal_mentions_no_network_and_confidence(capsys):
    report = analyze(b"SGVsbG8=")
    text = render_terminal(report, color=False)
    assert "ADIN" in text
    assert "Confidence" in text
    assert "does not execute input" in text


def test_cli_pipe_smoke(tmp_path):
    root = Path(__file__).resolve().parents[1]
    env_path = str(root / "src")
    import os
    env = os.environ.copy()
    env["PYTHONPATH"] = env_path
    proc = subprocess.run([sys.executable, "-m", "adin.cli", "--json", "-"], input=b"SGVsbG8=", capture_output=True, env=env)
    assert proc.returncode == 0, proc.stderr.decode()
    assert json.loads(proc.stdout)["input"]["length_bytes"] == 8


def test_base91_canonical_round_trip():
    from adin.detectors.encodings import _b91encode
    value = b"Hello world, ADIN detects basE91 locally!"
    encoded = _b91encode(value)
    report = analyze(encoded.encode(), max_depth=1)
    match = next(d for d in report.layers[0].detections if d.name == "basE91")
    assert match.decoded_bytes == value


def test_base45_canonical_round_trip():
    from adin.detectors.encodings import _b45encode
    value = b"ADIN QR"
    encoded = _b45encode(value)
    report = analyze(encoded.encode(), max_depth=1)
    match = next(d for d in report.layers[0].detections if d.name == "Base45")
    assert match.decoded_bytes == value


def test_utf16_bom_detection_and_nested_text():
    report = analyze("Hello, ADIN".encode("utf-16"), max_depth=2)
    assert any(d.category == "text_encoding" for d in report.layers[0].detections)
    assert len(report.layers) >= 2


def test_pgp_armor_has_specific_detection():
    report = analyze(b"-----BEGIN PGP MESSAGE-----\nYWJj\n-----END PGP MESSAGE-----")
    assert any(d.name == "PGP armored data" for d in report.layers[0].detections)


def test_unix_modular_crypt_format_candidate():
    sample = b"$6$rounds=5000$saltstring$not-a-real-hash"
    report = analyze(sample)
    # Deliberately only structural: malformed/noncanonical values must not be presented as verified.
    assert any("Unix modular password hash" in d.name for d in report.layers[0].detections)


def test_source_launcher_runs_without_installation():
    root = Path(__file__).resolve().parents[1]
    proc = subprocess.run([str(root / "bin" / "adin"), "--version"], capture_output=True, text=True)
    assert proc.returncode == 0
    assert "ADIN 0.1.0" in proc.stdout


def test_installer_creates_local_symlink_without_package_download(tmp_path):
    root = Path(__file__).resolve().parents[1]
    home = tmp_path / "home"
    home.mkdir()
    import os
    env = os.environ.copy()
    env["HOME"] = str(home)
    proc = subprocess.run([str(root / "install.sh")], capture_output=True, text=True, env=env)
    assert proc.returncode == 0, proc.stderr
    installed = home / ".local" / "bin" / "adin"
    assert installed.is_symlink()
    check = subprocess.run([str(installed), "--version"], capture_output=True, text=True, env=env)
    assert check.returncode == 0
    assert "ADIN 0.1.0" in check.stdout


def test_installer_refuses_to_overwrite_existing_command(tmp_path):
    root = Path(__file__).resolve().parents[1]
    home = tmp_path / "home"
    bindir = home / ".local" / "bin"
    bindir.mkdir(parents=True)
    existing = bindir / "adin"
    existing.write_text("original command", encoding="utf-8")
    import os
    env = os.environ.copy()
    env["HOME"] = str(home)
    proc = subprocess.run([str(root / "install.sh")], capture_output=True, text=True, env=env)
    assert proc.returncode != 0
    assert existing.read_text(encoding="utf-8") == "original command"


def test_percent_and_quoted_printable_encodings():
    percent = analyze(b"%48%65%6C%6C%6F", max_depth=1)
    assert next(d for d in percent.layers[0].detections if d.name == "Percent / URL encoding").decoded_bytes == b"Hello"
    qp = analyze(b"Hello=20World", max_depth=1)
    assert next(d for d in qp.layers[0].detections if "Quoted-printable" in d.name).decoded_bytes == b"Hello World"


def test_morse_and_rot13_candidates():
    morse = analyze(b"... --- ... / .... . .-.. .--.", max_depth=1)
    assert any(d.name == "Morse code" and d.decoded_bytes == b"SOS HELP" for d in morse.layers[0].detections)
    rot = analyze(b"uryyb jbeyq", max_depth=0)
    assert any(d.name.startswith("ROT13") and d.decoded_bytes == b"hello world" for d in rot.layers[0].detections)


def test_openssl_salted_header_is_not_reinterpreted_as_generic_base64():
    report = analyze(b"Salted__12345678and-remaining-ciphertext", max_depth=3)
    assert any(d.name == "OpenSSL salted-data header" for d in report.layers[0].detections)
    assert len(report.layers) == 1


def test_der_sequence_candidate():
    report = analyze(b"\x30\x03\x02\x01\x05")
    match = next(d for d in report.layers[0].detections if d.name == "ASN.1 DER SEQUENCE candidate")
    assert match.parameters["exact_length_match"] is True
