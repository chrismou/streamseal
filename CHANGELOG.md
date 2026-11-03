# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `StreamSeal` with `encrypt()` and `decrypt()` over PHP stream resources, using libsodium
  secretstream (XChaCha20-Poly1305) in fixed-size chunks with a FINAL tag on the last one.
- `StreamSeal::generateKey()` for a random 32-byte per-file key.
- Configurable chunk size via the constructor (default 64 KiB).
- `sealedLength()` and `plaintextLength()` size helpers.
- `DecryptionFailedException` for wrong key, tampering, truncation, trailing data and missing header;
  `InvalidKeyException` for keys of the wrong length; `StreamException` for failed reads and short writes.
  All implement `StreamSealExceptionInterface`.
- `Psr7\Psr7StreamSeal` adapter taking PSR-7 `StreamInterface` in and out, backed by `Psr7\Psr7StreamWrapper`
  which exposes any PSR-7 stream as a native resource. `psr/http-message` is suggested, not required.
