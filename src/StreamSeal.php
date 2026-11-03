<?php

declare(strict_types=1);

namespace Chrismou\StreamSeal;

use Chrismou\StreamSeal\Exception\DecryptionFailedException;
use Chrismou\StreamSeal\Exception\InvalidKeyException;
use Chrismou\StreamSeal\Exception\StreamException;
use InvalidArgumentException;
use SensitiveParameter;
use SodiumException;

/**
 * Streaming authenticated encryption built on libsodium's secretstream (XChaCha20-Poly1305).
 *
 * The sealed layout is the 24-byte stream header followed by fixed-size chunks, each
 * carrying its own 17-byte authentication tag; the last chunk is tagged FINAL so a
 * truncated stream fails to decrypt. Memory stays at one chunk regardless of input size.
 *
 * The chunk size is not recorded in the sealed stream, so decrypt with the same
 * chunk size that was used to encrypt.
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

    /**
     * @param  int  $chunkBytes  plaintext bytes per chunk; must match between encrypt and decrypt
     *
     * @throws InvalidArgumentException when the chunk size is not positive
     */
    public function __construct(public int $chunkBytes = self::DEFAULT_CHUNK_BYTES)
    {
        if ($chunkBytes < 1) {
            throw new InvalidArgumentException('Chunk size must be at least 1 byte.');
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
     * @throws StreamException when $in cannot be read or $out cannot be fully written
     */
    public function encrypt($in, $out, #[SensitiveParameter] string $key): void
    {
        self::assertKey($key);

        [$state, $header] = sodium_crypto_secretstream_xchacha20poly1305_init_push($key);

        $this->write($out, $header);

        $chunk = $this->readExactly($in, $this->chunkBytes);

        // Look one chunk ahead so the last one (possibly empty, for empty input) gets the FINAL tag.
        do {
            $next = feof($in) ? '' : $this->readExactly($in, $this->chunkBytes);
            $tag = $next === ''
                ? SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL
                : SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;

            $this->write($out, sodium_crypto_secretstream_xchacha20poly1305_push($state, $chunk, '', $tag));

            $chunk = $next;
        } while ($chunk !== '');
    }

    /**
     * Decrypt a sealed stream from $in, writing plaintext to $out.
     *
     * Each chunk is verified before it is written, so nothing unauthenticated reaches $out,
     * but chunks preceding a failure will already have been written when the exception is thrown.
     *
     * @param  resource  $in
     * @param  resource  $out
     *
     * @throws InvalidKeyException when the key is the wrong length
     * @throws DecryptionFailedException when the key is wrong or the stream is corrupt, truncated or has trailing data
     * @throws StreamException when $in cannot be read or $out cannot be fully written
     */
    public function decrypt($in, $out, #[SensitiveParameter] string $key): void
    {
        self::assertKey($key);

        $header = $this->readExactly($in, self::HEADER_BYTES);

        if (strlen($header) !== self::HEADER_BYTES) {
            throw DecryptionFailedException::missingHeader();
        }

        try {
            $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $key);
        } catch (SodiumException $e) {
            throw DecryptionFailedException::invalidHeader($e);
        }

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

            $this->write($out, $plain);

            if ($tag === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) {
                if ($this->readExactly($in, 1) !== '') {
                    throw DecryptionFailedException::trailingData();
                }

                return;
            }
        }

        throw DecryptionFailedException::truncated();
    }

    /**
     * Size in bytes of the sealed stream produced for the given plaintext size.
     */
    public function sealedLength(int $plaintextLength): int
    {
        if ($plaintextLength < 0) {
            throw new InvalidArgumentException('Plaintext length cannot be negative.');
        }

        $chunks = max(1, intdiv($plaintextLength + $this->chunkBytes - 1, $this->chunkBytes));

        return self::HEADER_BYTES + $plaintextLength + $chunks * self::TAG_BYTES;
    }

    /**
     * Size in bytes of the plaintext inside a well-formed sealed stream of the given size.
     */
    public function plaintextLength(int $sealedLength): int
    {
        $minimum = self::HEADER_BYTES + self::TAG_BYTES;

        if ($sealedLength < $minimum) {
            throw new InvalidArgumentException(sprintf('A sealed stream is at least %d bytes.', $minimum));
        }

        $body = $sealedLength - self::HEADER_BYTES;
        $sealedChunkBytes = $this->chunkBytes + self::TAG_BYTES;
        $chunks = intdiv($body + $sealedChunkBytes - 1, $sealedChunkBytes);

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
     * Read up to $length bytes, looping because non-local streams may return short reads.
     *
     * @param  resource  $stream
     *
     * @throws StreamException when a read fails outright
     */
    private function readExactly($stream, int $length): string
    {
        $buffer = '';

        while (! feof($stream)) {
            $remaining = $length - strlen($buffer);

            if ($remaining < 1) {
                break;
            }

            $read = fread($stream, $remaining);

            if ($read === false) {
                throw StreamException::readFailed();
            }

            if ($read === '') {
                break;
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

        $written = fwrite($stream, $bytes);

        if ($written !== strlen($bytes)) {
            throw StreamException::shortWrite(strlen($bytes), $written === false ? 0 : $written);
        }
    }
}
