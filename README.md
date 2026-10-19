# ADIN — Automated Cryptographic Inspector

**ADIN** is an offline-first command-line inspector for encoded strings, cryptographic container formats, hash-shaped values, classical-cipher candidates, and common binary/file signatures. It is designed for Linux, CTF practice, developer debugging, and first-pass digital investigation.

> **Important limitation:** no detector can identify every encoding or cryptographic algorithm in the world from arbitrary bytes alone. Many formats overlap, hash algorithms can share digest lengths, and well-designed ciphertext intentionally looks random. ADIN reports ranked candidates, evidence, confidence labels, and limitations instead of pretending ambiguity does not exist.

## Design goals

- **Offline by default:** no HTTP requests, APIs, telemetry, or AI models.
- **Fast first-pass analysis:** lightweight deterministic checks and no brute force.
- **Layer-aware:** decodes supported representations in bounded steps (Base64 of hex, for example).
- **Evidence before claims:** each result explains why it matched and what that match does not prove.
- **Machine-readable:** optional JSON output for scripts and other tools.
- **Safe handling:** analysis does not execute inputs or decoded data, does not crack password hashes, and does not modify source files.
- **Extensible modules:** detectors can be added without turning the CLI into a monolith.

## Requirements

- Python 3.10 or newer
- No third-party runtime dependencies

## Install

The project has no third-party runtime dependencies. For a fully local install, unpack the source archive and run:

```bash
chmod +x bin/adin install.sh
./bin/adin --version
./install.sh
```

The installer creates a symlink at `~/.local/bin/adin` and refuses to overwrite an unrelated existing command. If that directory is not on your `PATH`, the installer prints the exact shell-profile line to add. No Python package download, API key, model, or network service is needed.

You can also run ADIN directly from the project directory without installing it:

```bash
./bin/adin 'SGVsbG8='
```

For maintainers who prefer a standard Python package install (this may require build tooling to already be available, or access to a package index):

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
adin --version
```

To run the test suite in a development environment with pytest installed:

```bash
python -m pytest
```

## Shell completion and manual page

The local installer also installs tab completion for Bash, Zsh, and Fish, plus a manual page.

After running `./install.sh`, restart the terminal (or reload your current shell configuration). To see option completions, type a **space after the command** and then press Tab:

```bash
adin <TAB>        # option and file suggestions
adin --<TAB>      # options such as --verbose, --json, --file
adin --depth <TAB> # supported depth values
```

Pressing Tab immediately after `adin` with **no trailing space** completes the command name itself; shells normally do not offer its arguments until the cursor is in the argument position.

Open the full manual with:

```bash
man adin
adin --help
```

The manual is installed to `~/.local/share/man/man1/adin.1`. If your system's man search path does not include that directory, use `man -M "$HOME/.local/share/man" adin`. The installer adds the local manual path and completion setup to Bash/Zsh configuration files once, without replacing existing files.

## Usage

```bash
# A Base64 example
adin 'SGVsbG8='

# Hexadecimal bytes
adin '48656c6c6f'

# Verbose mode: show all candidates and parameters
adin --verbose 'U0dWc2JHOD0='

# Inspect file bytes without modifying the file
adin --file ./sample.bin

# Read input through a pipe
printf '%s' 'SGVsbG8=' | adin -

# JSON report for automation
adin --json 'SGVsbG8=' > report.json

# Stop recursive decoding after one layer
adin --depth 1 'U0dWc2JHOD0='

# Change maximum accepted input size (default: 1 MiB)
adin --max-bytes 2097152 --file ./sample.bin
```

Wrap inputs in quotes when shell metacharacters, spaces, dollar signs, or backslashes are present. `--file` analyzes exact bytes; literal input arguments are encoded as UTF-8 before analysis. When input is passed through standard input, ADIN reads at most the configured limit plus one byte to check the size cap.

## Current built-in coverage (v0.1.0)

### Text encodings and representations

- Hexadecimal / Base16-like strings
- Base64 and URL-safe Base64
- Base32
- Base45, Base58 using the Bitcoin alphabet (including Base58Check checksum verification when valid), Base85 and Ascii85 candidates
- basE91 (canonical round-trip checked)
- Percent / URL encoding
- HTML character references
- Common backslash and Unicode escape sequences, `U+` Unicode code point notation
- Decimal/octal byte-value lists, quoted-printable, UTF BOM recognition, and UTF-16 heuristic detection
- 8-bit binary octets
- A limited alphanumeric Morse code table

### Cryptographic structures and tokens

- PEM-style armor labels
- OpenSSH public-key lines
- PGP armor markers
- Compact JWS / signed-JWT candidates
- Compact JWE candidates
- Fernet token candidates
- OpenSSL legacy `Salted__` data header
- ASN.1 DER sequence candidates, OpenSSH SHA-256 fingerprint format
- bcrypt, Argon2, scrypt, phpass, Unix modular-crypt (MD5-crypt / SHA-256-crypt / SHA-512-crypt / yescrypt), and selected PBKDF2 serialization prefixes

ADIN recognizes structure only; it does not verify signatures, validate certificates, decrypt data, or verify password hashes.

### Hash-shaped values

It reports candidate algorithms for common hexadecimal digest lengths, including MD5/NTLM-length (32 hex chars), SHA-1/RIPEMD-160-length (40), SHA-224-length (56), 256-bit digest-length (64), 384-bit digest-length (96), and 512-bit digest-length (128) values. These are intentionally marked **possible hash** because length is not proof and several algorithms share lengths.

### Binary and statistical observations

- GZIP, BZIP2, XZ, ZIP, RAR, 7z, ELF, PE-family, PNG, GIF, JPEG, PDF, SQLite signatures
- zlib-header candidate check
- Byte entropy, unique-byte count, printable-ASCII ratio, NUL count, UTF-8 validity
- Heuristic Atbash/Caesar candidates when a small English-word score gives a useful signal

Statistical observations such as high entropy are not classified as encryption proof. In this first release, compressed containers are recognized but not automatically decompressed, reducing exposure to decompression bombs.

## How confidence works

Confidence is a measure of **pattern fit**, not proof that the bytes are valid, authentic, safe, or produced by a particular cryptographic algorithm. The terminal output includes direct evidence and warnings; use `--verbose` for all ranked candidates and detector parameters.

## Architecture

```text
CLI
 └─ pipeline
     ├─ structured-format and magic-signature recognizers
     ├─ encoding detectors
     ├─ statistics and binary checks
     ├─ bounded nested-decoding loop
     └─ terminal / JSON report
```

A detector returns a normalized `Detection` containing a name, category, confidence score, evidence, limitations, optional parameters, and (where safe and meaningful) decoded bytes. The pipeline ranks results, fingerprints each layer to prevent cycles, and respects the configured recursion depth.

## Security and privacy notes

- ADIN has no network-capable feature and no analytics/telemetry.
- Input and decoded bytes are treated as data only; they are never executed as code or shell commands.
- Inputs are bounded by `--max-bytes`; recursive analysis is bounded by `--depth`.
- Output previews are truncated and escaped to make control bytes visible.
- Avoid posting reports publicly if the input itself contains secrets. A SHA-256 fingerprint is included to identify the original bytes without printing the entire content.
- The project is an analysis aid, not a cryptographic validation suite or forensic chain-of-custody system.

## Current limitations and roadmap

ADIN v0.1.0 is a working extensible foundation, not an exhaustive catalog of all schemes. Not yet covered comprehensively: every Base-N family, all language-specific escape syntaxes, every password-hash variant, every key/container format, all compression/archive algorithms, binary protocol parsers, full cryptanalysis, and algorithm identification for arbitrary ciphertext. Some overlapping encodings can generate multiple candidates. Classical cipher scoring is English-biased and deliberately conservative.

Potential future improvements:

1. Add a curated format registry and fixture corpus with known positives, negatives, and ambiguous cases.
2. Expand Base-N and common application-specific token formats.
3. Add optional, safe archive metadata inspection without extracting files.
4. Add provenance notes and stable JSON schema versioning.
5. Add per-detector performance benchmarks and fuzz testing.
6. Add offline plugins for other detector families while retaining strict input and runtime limits.

## Contributing

New detectors should include positive tests, negative tests, malformed-input tests, an explanation of what the signature proves, and explicit limitations. Prefer deterministic local parsing over broad guesses. Never raise confidence merely because a payload looks random.

## License

MIT. See [LICENSE](LICENSE).

See [SECURITY.md](SECURITY.md) for safe-use boundaries and security assumptions.

## Human-readable terminal summary

The default terminal view starts with the best-supported interpretation, shows the category and confidence, displays a bounded decoded preview when available, explains whether the result is encryption, and lists alternative matches separately. Low-confidence alternatives include a caution to reduce false certainty. Use `--verbose` for technical statistics, detector evidence, parameters, limitations, and all candidate matches. Use `--json` for machine-readable output.

Example:

```console
$ adin '48656c6c6f'
╭────────────────────────────────────────────────╮
│                 ADIN ANALYSIS                  │
╰────────────────────────────────────────────────╯
ADIN v0.1.0 | Offline cryptographic & encoding inspector

INPUT          : 48656c6c6f
VERDICT        : HEXADECIMAL ENCODING
CATEGORY       : Data Encoding
CONFIDENCE     : Very High (96%)
DECODED        : Hello

WHAT IS IT?
Hexadecimal represents each byte using two hexadecimal digits.

IS IT ENCRYPTION?
No. This is an encoding, not encryption; it can be reversed without
a secret key.

ALTERNATIVE MATCHES
- Base58 (Bitcoin alphabet): Moderate (72%)
  Base58 has no universal marker; many identifiers and random
  strings share this alphabet.

FINAL RESULT
Type           : HEXADECIMAL ENCODING
Data           : Hello
Classification : Encoding, not encryption
```
