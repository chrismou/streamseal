# StreamSeal

Streaming authenticated file encryption for PHP, built on libsodium's secretstream
(XChaCha20-Poly1305). Encrypts a stream of any size in flat memory. Tampering, truncation,
appended data and a wrong key are all detected on decrypt. Zero dependencies beyond `ext-sodium`,
with an optional PSR-7 adapter.

## What it's for

Encrypting files at rest without ever holding the whole file in memory. Typical uses:

- Encrypting user uploads before they are written to local disk or S3, and decrypting them straight
  into the HTTP response on download.
- Encrypting backups, exports or log archives as they are produced.
- Any case where you need a file to be unreadable without its key, and want to know on the way
  back out that it has not been modified, truncated or had data appended.

It is symmetric and per-file: you generate a random key for each file, encrypt the file with it,
and keep the key somewhere safe (typically encrypted in your database alongside the file record).
Decryption needs the same key. Never reuse a key for another file.

## Requirements

- PHP 8.2+
- `ext-sodium` (enabled by default since PHP 7.2)

## Installation

```bash
composer require chrismou/streamseal
```

## Usage

```php
use Chrismou\StreamSeal\StreamSeal;

$seal = new StreamSeal();

// One random 32-byte key per file. Store it somewhere safe, e.g. encrypted in your database.
$key = StreamSeal::generateKey();

// Encrypt: any readable stream in, any writable stream out.
$seal->encrypt(fopen('report.pdf', 'rb'), fopen('report.pdf.sealed', 'wb'), $key);

// Decrypt: for example straight to the HTTP response.
$seal->decrypt(fopen('report.pdf.sealed', 'rb'), fopen('php://output', 'wb'), $key);

// Wipe the key from memory once you are done with it.
sodium_memzero($key);
```

Memory use is a few chunks (64 KiB each by default) regardless of file size, so it is safe to use
on uploads and downloads of any size.

Both arguments must be open, distinct stream resources. The input must be a blocking stream: one
that returns no data before its end throws a `StreamException`.

### Sizes

```php
$seal->sealedLength(strlen($plaintext)); // bytes the sealed stream will occupy
$seal->plaintextLength(filesize('report.pdf.sealed')); // bytes of plaintext inside, for Content-Length
```

`plaintextLength()` throws `InvalidArgumentException` for a size no sealed stream can have.

### Chunk size

```php
$seal = new StreamSeal(chunkBytes: 1_048_576);
```

Any size from 1 byte to 1 GiB (`StreamSeal::MAX_CHUNK_BYTES`) is accepted. Peak memory is roughly
three times the chunk size.

The chunk size is not stored in the sealed stream, so decrypt with the same size you encrypted
with. A different size fails with `DecryptionFailedException`.

### PSR-7

Install `psr/http-message` and use the adapter with any PSR-7 stream implementation. It does not
need the stream to be resource-backed.

```php
use Chrismou\StreamSeal\Psr7\Psr7StreamSeal;

$seal = new Psr7StreamSeal();

$seal->encrypt($request->getBody(), $sealedStream, $key);

$sealedStream->rewind();
$seal->decrypt($sealedStream, $responseBody, $key);
```

Both streams are used from their current position, so rewind one that has already been read or
written. Create the output stream with your PSR-17 factory, for example `$factory->createStream()`
or `$factory->createStreamFromFile('php://temp', 'w+b')`, then attach it to the response with
`withBody()`.

## Errors

Every exception implements `Chrismou\StreamSeal\Exception\StreamSealExceptionInterface`.

| Exception | When |
|---|---|
| `InvalidKeyException` | The key is not exactly 32 bytes. |
| `InvalidArgumentException` | A chunk size out of range, a stream argument that is not an open stream, or a size no sealed stream can have. |
| `DecryptionFailedException` | Wrong key, modified data, truncated stream, data after the final chunk, or no header. |
| `StreamException` | The input could not be read or stalled, the output could not be fully written, or a PSR-7 stream threw (attached as the previous exception). |

Each chunk is verified before it is written, so unauthenticated bytes never reach the output.
Chunks before the failing one will already have been written when `DecryptionFailedException`
is thrown, which matters if you are streaming to a browser.

## What it is not

It does not manage, derive or wrap keys, and it is not password based. You generate a key per
file and are responsible for storing it.

## Format

A 24-byte secretstream header, then chunks of `chunkBytes` plaintext each sealed with a 17-byte
authentication tag. The last chunk is tagged FINAL, so a stream that ends without one is rejected.

## License

MIT
