# StreamSeal

Streaming authenticated file encryption for PHP, built on libsodium's secretstream
(XChaCha20-Poly1305). Encrypts a stream of any size in flat memory. Tampering, truncation,
appended data and a wrong key are all detected on decrypt. Zero dependencies beyond `ext-sodium`, with an optional PSR-7 adapter.

## Requirements

- PHP 8.2+
- `ext-sodium` (bundled with PHP since 7.2)

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
```

Memory use is one chunk (64 KiB by default) regardless of file size, so it is safe to use on
uploads and downloads of any size.

### Sizes

```php
$seal->sealedLength(strlen($plaintext)); // bytes the sealed stream will occupy
$seal->plaintextLength(filesize('report.pdf.sealed')); // bytes of plaintext inside, for Content-Length
```

### Chunk size

```php
$seal = new StreamSeal(chunkBytes: 1_048_576);
```

The chunk size is not stored in the sealed stream, so decrypt with the same size you encrypted with.

### PSR-7

Install `psr/http-message` and use the adapter with any PSR-7 stream implementation. It does not
need the stream to be resource-backed.

```php
use Chrismou\StreamSeal\Psr7\Psr7StreamSeal;

$seal = new Psr7StreamSeal();

$seal->encrypt($request->getBody(), $sealedStream, $key);
$seal->decrypt($sealedStream, $responseBody, $key);
```

Create the output stream with your PSR-17 factory, for example `$factory->createStream()` or
`$factory->createStreamFromFile('php://temp', 'w+b')`, then attach it to the response with `withBody()`.

## Errors

Every exception implements `Chrismou\StreamSeal\Exception\StreamSealExceptionInterface`.

| Exception | When |
|---|---|
| `InvalidKeyException` | The key is not exactly 32 bytes. |
| `DecryptionFailedException` | Wrong key, modified data, truncated stream, data after the final chunk, or no header. |
| `StreamException` | The input stream could not be read or the output stream could not be fully written. |

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
