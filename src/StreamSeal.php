<?php

declare(strict_types=1);

namespace Chrismou\StreamSeal;

use Chrismou\StreamSeal\Exception\DecryptionFailedException;
use Chrismou\StreamSeal\Exception\InvalidArgumentException;
use Chrismou\StreamSeal\Exception\InvalidKeyException;
use Chrismou\StreamSeal\Exception\StreamException;
use SensitiveParameter;
use SodiumException;

/**
 * Streaming authenticated encryption built on libsodium's secretstream (XChaCha20-Poly1305).
 *
 * The sealed layout is the 24-byte stream header followed by fixed-size chunks, each
 * carrying its own 17-byte authentication tag; the last chunk is tagged FINAL so a
 * truncated stream fails to decrypt. Memory stays at a few chunks regardless of input size.
 *
 * The chunk size is not recorded in the sealed stream, so decrypt with the same
 * chunk size that was used to encrypt.
 *
 * Streams must be blocking: a read that returns nothing before end of file is reported as
 * a StreamException rather than treated as the end of the input.
 */
final readonly class StreamSeal
{
    /** Length of a key in bytes. */
    public const KEY_BYTES = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES;

    /** Length of the header that starts every sealed stream. */
    public const HEADER_BYTES = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES;

    /** Authentication tag bytes added to every chunk. */
    public const TAG_BYTES = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;

    /** Plaintext bytes per chunk unless the constructor is given another size. */
    public const DEFAULT_CHUNK_BYTES = 65_536;

    /** Largest accepted chunk size (1 GiB), which bounds per-chunk memory and keeps the size arithmetic in range. */
    public const MAX_CHUNK_BYTES = 1_073_741_824;

    /**
     * @param  int  $chunkBytes  plaintext bytes per chunk; must match between encrypt and decrypt
     *
     * @throws InvalidArgumentException when the chunk size is below 1 or above MAX_CHUNK_BYTES
     */
    public function __construct(public int $chunkBytes = self::DEFAULT_CHUNK_BYTES)
    {
        if ($chunkBytes < 1 || $chunkBytes > self::MAX_CHUNK_BYTES) {
            throw new InvalidArgumentException(sprintf(
                'Chunk size must be between 1 and %d bytes, %d given.',
                self::MAX_CHUNK_BYTES,
                $chunkBytes,
            ));
        }
    }

    /**
     * Generate a fresh random key. Use one key per sealed stream.
     */
    public static function generateKey(): string
    {
        return sodium_crypto_secretstream_xchacha20poly1305_keygen();
    }

    /**
     * Encrypt everything readable from $in and write the sealed stream to $out.
     *
     * @param  resource  $in
     * @param  resource  $out
     *
     * @throws InvalidKeyException when the key is the wrong length
     * @throws InvalidArgumentException when $in or $out is not an open stream resource, or they are the same resource
     * @throws StreamException when $in cannot be read, stalls before its end, or $out cannot be fully written
     */
    public function encrypt($in, $out, #[SensitiveParameter] string $key): void
    {
        self::assertKey($key);
        self::assertStreams($in, $out);

        [$state, $header] = sodium_crypto_secretstream_xchacha20poly1305_init_push($key);

        try {
            $this->write($out, $header);

            $chunk = $this->readExactly($in, $this->chunkBytes);

            // Look one chunk ahead so the last one (possibly empty, for empty input) gets the FINAL tag.
            // readExactly() only comes back short at end of input, so an empty look-ahead is reliable.
            do {
                $next = feof($in) ? '' : $this->readExactly($in, $this->chunkBytes);
                $tag = $next === ''
                    ? SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL
                    : SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;

                $this->write($out, sodium_crypto_secretstream_xchacha20poly1305_push($state, $chunk, '', $tag));

                $chunk = $next;
            } while ($chunk !== '');
        } finally {
            sodium_memzero($state);
        }
    }

    /**
     * Decrypt a sealed stream from $in, writing plaintext to $out.
     *
     * Each chunk is verified before it is written, so nothing unauthenticated reaches $out, and the
     * final chunk is held back until the stream is confirmed to end after it. Chunks preceding a
     * failure will already have been written when the exception is thrown.
     *
     * @param  resource  $in
     * @param  resource  $out
     *
     * @throws InvalidKeyException when the key is the wrong length
     * @throws InvalidArgumentException when $in or $out is not an open stream resource, or they are the same resource
     * @throws DecryptionFailedException when the key is wrong or the stream is corrupt, truncated or has trailing data
     * @throws StreamException when $in cannot be read, stalls before its end, or $out cannot be fully written
     */
    public function decrypt($in, $out, #[SensitiveParameter] string $key): void
    {
        self::assertKey($key);
        self::assertStreams($in, $out);

        $header = $this->readExactly($in, self::HEADER_BYTES);

        if (strlen($header) !== self::HEADER_BYTES) {
            throw DecryptionFailedException::missingHeader();
        }

        try {
            $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $key);
        } catch (SodiumException $e) {
            // Only a bad header or key length throws here and both are checked above; kept so a SodiumException can never escape.
            throw DecryptionFailedException::invalidHeader($e);
        }

        try {
            $sealedChunkBytes = $this->chunkBytes + self::TAG_BYTES;

            while (($sealedChunk = $this->readExactly($in, $sealedChunkBytes)) !== '') {
                try {
                    $result = sodium_crypto_secretstream_xchacha20poly1305_pull($state, $sealedChunk);
                } catch (SodiumException $e) {
                    throw DecryptionFailedException::corruptChunk($e);
                }

                if ($result === false) {
                    throw DecryptionFailedException::corruptChunk();
                }

                [$plain, $tag] = $result;

                if ($tag === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) {
                    // Confirm the stream ends here before releasing the last chunk, so trailing data leaves it unwritten.
                    if ($this->readExactly($in, 1) !== '') {
                        throw DecryptionFailedException::trailingData();
                    }

                    $this->write($out, $plain);

                    return;
                }

                $this->write($out, $plain);
            }

            throw DecryptionFailedException::truncated();
        } finally {
            sodium_memzero($state);
        }
    }

    /**
     * Size in bytes of the sealed stream produced for the given plaintext size.
     *
     * @throws InvalidArgumentException when the length is negative or the result would not fit in an int
     */
    public function sealedLength(int $plaintextLength): int
    {
        if ($plaintextLength < 0) {
            throw new InvalidArgumentException('Plaintext length cannot be negative.');
        }

        $chunks = max(1, intdiv($plaintextLength, $this->chunkBytes) + ($plaintextLength % $this->chunkBytes === 0 ? 0 : 1));

        if (
            $chunks > intdiv(PHP_INT_MAX - self::HEADER_BYTES, self::TAG_BYTES)
            || $plaintextLength > PHP_INT_MAX - self::HEADER_BYTES - $chunks * self::TAG_BYTES
        ) {
            throw new InvalidArgumentException('The sealed length would exceed PHP_INT_MAX.');
        }

        return self::HEADER_BYTES + $plaintextLength + $chunks * self::TAG_BYTES;
    }

    /**
     * Size in bytes of the plaintext inside a sealed stream of the given size.
     *
     * @throws InvalidArgumentException when no sealed stream with this chunk size can have that length
     */
    public function plaintextLength(int $sealedLength): int
    {
        $minimum = self::HEADER_BYTES + self::TAG_BYTES;

        if ($sealedLength < $minimum) {
            throw new InvalidArgumentException(sprintf('A sealed stream is at least %d bytes.', $minimum));
        }

        $body = $sealedLength - self::HEADER_BYTES;
        $sealedChunkBytes = $this->chunkBytes + self::TAG_BYTES;
        $partialChunkBytes = $body % $sealedChunkBytes;

        // A partial last chunk still carries a whole tag, so anything shorter than one cannot be a chunk.
        if ($partialChunkBytes !== 0 && $partialChunkBytes < self::TAG_BYTES) {
            throw new InvalidArgumentException(sprintf(
                'No sealed stream with %d-byte chunks can be %d bytes long.',
                $this->chunkBytes,
                $sealedLength,
            ));
        }

        $chunks = intdiv($body, $sealedChunkBytes) + ($partialChunkBytes === 0 ? 0 : 1);

        return $body - $chunks * self::TAG_BYTES;
    }

    /**
     * @throws InvalidKeyException
     */
    private static function assertKey(#[SensitiveParameter] string $key): void
    {
        if (strlen($key) !== self::KEY_BYTES) {
            throw InvalidKeyException::wrongLength(self::KEY_BYTES, strlen($key));
        }
    }

    /**
     * Reject anything that is not an open stream resource before a byte is written anywhere.
     *
     * @throws InvalidArgumentException
     */
    private static function assertStreams(mixed $in, mixed $out): void
    {
        if (! is_resource($in) || get_resource_type($in) !== 'stream') {
            throw new InvalidArgumentException('The input must be an open stream resource.');
        }

        if (! is_resource($out) || get_resource_type($out) !== 'stream') {
            throw new InvalidArgumentException('The output must be an open stream resource.');
        }

        if ($in === $out) {
            throw new InvalidArgumentException('The input and output must be different streams.');
        }
    }

    /**
     * Read $length bytes, looping because non-local streams may return short reads. Comes back
     * short only at end of input: an empty read before EOF is a stall and is reported as such.
     *
     * @param  resource  $stream
     *
     * @throws StreamException when a read fails outright or returns nothing before end of file
     */
    private function readExactly($stream, int $length): string
    {
        $buffer = '';

        while (! feof($stream)) {
            $remaining = $length - strlen($buffer);

            if ($remaining < 1) {
                break;
            }

            error_clear_last();
            $read = @fread($stream, $remaining);

            if ($read === false) {
                throw StreamException::readFailed(error_get_last()['message'] ?? null);
            }

            if ($read === '' && ! feof($stream)) {
                throw StreamException::readStalled();
            }

            $buffer .= $read;
        }

        return $buffer;
    }

    /**
     * Write all of $bytes to the stream, failing loudly on a short write.
     *
     * @param  resource  $stream
     *
     * @throws StreamException
     */
    private function write($stream, string $bytes): void
    {
        if ($bytes === '') {
            return;
        }

        error_clear_last();
        $written = @fwrite($stream, $bytes);

        if ($written !== strlen($bytes)) {
            throw StreamException::shortWrite(
                strlen($bytes),
                $written === false ? 0 : $written,
                $written === false ? (error_get_last()['message'] ?? null) : null,
            );
        }
    }
}
