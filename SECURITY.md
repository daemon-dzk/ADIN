# Security Notes

ADIN is intended for local, first-pass analysis of data the operator is authorized to inspect.

- The core application makes no network requests and uses no AI service.
- Decoded data is never evaluated, executed, extracted to disk, or passed to a shell.
- File input is opened read-only; a byte limit and recursion-depth limit are applied.
- Compression formats are signature-checked but not automatically decompressed in v0.1.0.
- Do not treat a detector result as proof of authenticity, safety, algorithm identity, or forensic validity.
- The tool does not verify signatures, decrypt ciphertext, or attempt password/hash cracking.
- Reports include a SHA-256 fingerprint of the original input. If that fingerprint could itself be sensitive in your environment, handle the report accordingly.

If you find a security issue in ADIN itself, reproduce it with a minimal test case and report the affected version and Python version. Avoid attaching real secrets or private evidence.
