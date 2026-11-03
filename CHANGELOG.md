# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `encrypt()` no longer treats a read that returns nothing before end of file as the end of the
  input. A non-blocking, timed-out or otherwise stalled stream used to produce a valid sealed stream
  of a truncated prefix, or an undecryptable stream if the empty read landed mid-input. It now throws
  `StreamException`.
- `decrypt()` checks for data after the final chunk before writing that chunk, so an appended-to
  stream no longer has its last chunk written to the output before the failure is reported.
- `sealedLength()` and `plaintextLength()` throw `InvalidArgumentException` instead of a `TypeError`
  when the arithmetic would overflow, and `plaintextLength()` rejects sizes no sealed stream can have
  instead of returning a wrong or negative number.
- `encrypt()` and `decrypt()` reject arguments that are not open stream resources, and the same
  resource passed as both input and output, with an `InvalidArgumentException` before anything is
  written. These used to surface as a `TypeError` or silent data loss.
- Failed reads and writes no longer emit a PHP notice before `StreamException` is thrown; the reason
  is included in the exception message instead.
- The PSR-7 wrapper detects another stream wrapper registered under its protocol name, checks that
  its own registration succeeded, and no longer leaks the input resource if the output cannot be
  wrapped.

### Added

- `Chrismou\StreamSeal\Exception\InvalidArgumentException`, which extends the global class and
  implements `StreamSealExceptionInterface`, so every exception the library throws carries the marker.
- `StreamException::readStalled()`, `StreamException::wrapFailed()` and
  `StreamException::fromPsr7Stream()`; `readFailed()` and `shortWrite()` accept an optional reason.
- `StreamSeal::MAX_CHUNK_BYTES` (1 GiB).
- The secretstream state is wiped with `sodium_memzero()` when `encrypt()` and `decrypt()` return.
- The PSR-7 adapter asks the stream for a whole chunk per read instead of PHP's 8 KiB default, and
  wraps anything thrown by the PSR-7 streams in a `StreamException`.
- Tests for stalled and failed reads, real files, FINAL tag placement, argument validation, overflow
  and impossible sizes in the length helpers, and PSR-7 failure paths. PHPUnit now fails on warnings,
  notices and deprecations.

### Changed

- Chunk sizes above `MAX_CHUNK_BYTES` are rejected by the constructor.
- Argument errors from the constructor, the length helpers and the PSR-7 adapter are thrown as
  `Chrismou\StreamSeal\Exception\InvalidArgumentException`. Code catching the global
  `InvalidArgumentException` is unaffected.
- `Psr7StreamWrapper::resourceFor()` throws `StreamException` rather than a plain `RuntimeException`.

## [0.1.0] - 2026-11-03

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

[Unreleased]: https://github.com/chrismou/streamseal/compare/0.1.0...HEAD
[0.1.0]: https://github.com/chrismou/streamseal/releases/tag/0.1.0
