# Changelog

## 0.1.0 — Initial public foundation

- Offline CLI for encoded strings, cryptographic container/token markers, hash-shaped values, common binary signatures, and limited classical-cipher candidates.
- Ranked detector results with evidence, confidence labels, caveats, bounded decoded previews, and JSON report support.
- Bounded nested decoding with cycle checks, input size limits, and recursion-depth controls.
- Source launcher and symlink installer that do not download dependencies.
- Unit tests for positive, ambiguous, malformed, CLI, JSON, and installation paths.

This release is intentionally a broad first-pass inspector, not an exhaustive registry of every encoding or a cryptographic validator.

## Readable terminal output update

- Replaced the raw detector dump as the default CLI view with a human-first analysis summary.
- Added explicit verdict, category, confidence, decoded preview, plain-language explanation, encryption assessment, alternatives, and final classification.
- Kept detailed technical statistics, evidence, parameters, and limitations available with `--verbose`; JSON output remains available with `--json`.
- Added tests for formatted HEX analysis and unknown-input uncertainty handling.

## Shell usability update

- Added Bash, Zsh, and Fish completions for ADIN flags, file paths, and supported numeric option values.
- Added a `man adin` manual page covering options, examples, limitations, and security notes.
- Extended the local installer to install completion/manual files and configure Bash/Zsh integration idempotently.

