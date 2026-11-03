# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`chrismou/streamseal` is a PHP 8.2+ library with no dependencies beyond `ext-sodium`. It encrypts
and decrypts PHP stream resources with libsodium's secretstream (XChaCha20-Poly1305), chunk by
chunk, so memory stays flat and tampering, truncation and trailing data are detected on decrypt.

0.1.0 is tagged and in use. Until 1.0.0, breaking changes are allowed but must be called out in the
CHANGELOG; the sealed stream format itself must never change (see invariants below).

## Commands

```bash
composer install

composer test              # phpunit
composer lint              # pint --test (PSR-12 + ordered/imported symbols)
composer lint:fix          # pint
composer analyse           # phpstan level 8 over src/ and tests/, no baseline, no ignores
composer test:coverage     # phpunit --coverage-text

vendor/bin/phpunit --filter testRoundTripsThroughEncryptAndDecrypt
```

CI (`.github/workflows/ci.yml`) runs lint, analyse and test on PHP 8.2 to 8.5. All three must be
clean before a change is considered done.

## Architecture

One class, `StreamSeal`, and three exceptions under `Exception/` that all implement the
`StreamSealExceptionInterface` marker.

- `encrypt($in, $out, $key)` writes the 24-byte header, then reads `chunkBytes` of plaintext at a
  time and pushes each as a sealed chunk. It looks one chunk ahead so the last chunk, which may be
  empty for empty input, gets the FINAL tag.
- `decrypt($in, $out, $key)` reads the header, then pulls `chunkBytes + 17` bytes at a time. A chunk
  is written only after it verifies. A FINAL tag ends the stream, and anything after it is an error.
  Running out of input before FINAL is a truncation error.
- `readExactly()` loops on short reads because non-local streams return fewer bytes than asked.
  `write()` throws on a short write rather than dropping bytes.
- `sealedLength()` / `plaintextLength()` are pure arithmetic over the layout above.
- `Psr7/Psr7StreamSeal` is a thin adapter: it checks readability/writability, wraps each PSR-7
  stream as a native resource via `Psr7/Psr7StreamWrapper` (a registered stream wrapper that
  delegates read/write/eof to the `StreamInterface` held in the stream context) and delegates to
  `StreamSeal`. There is one encryption implementation; never duplicate it for PSR-7.
  `psr/http-message` is a dev dependency and a `suggest`, never a `require`.

### Do-not-change invariants

The sealed layout (header, fixed-size chunks each with a trailing tag, FINAL on the last) and the
default chunk size of 65,536 bytes are a storage format. Data sealed by an earlier version must
decrypt with a later one. The chunk size is deliberately not written into the stream; if that ever
changes it needs a versioned header, not a silent change.

## Tests

- `tests/Unit/StreamSealTest.php` covers round trips, every failure mode, argument validation and
  stream edge cases. `tests/Unit/Psr7/Psr7StreamSealTest.php` covers the adapter. Helpers in
  `tests/Support`: `Streams` (memory streams), `OneByteReadStreamWrapper` (short reads),
  `UnwritableStreamWrapper` (failed writes), `InMemoryPsr7Stream` (a string-backed `StreamInterface`
  with no resource, so the adapter is proven not to rely on `detach()`).
- PHPStan runs over `tests/` too at level 8, so test code needs full type hints and array shapes.

## Conventions

- `declare(strict_types=1)`, `final` (often `final readonly`) classes, constructor promotion,
  docblocks on every method, array shape PHPDoc for arrays.
- Pint config: PSR-12, alphabetical imports, global classes imported (`use SodiumException;`), no unused imports.
- Use a plain hyphen `-` in all text; never Unicode dashes.
- README.md and CHANGELOG.md (Keep a Changelog, `[Unreleased]` section above dated releases) document the public
  API and must be updated alongside API changes.
