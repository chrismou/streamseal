<?php

declare(strict_types=1);

namespace Chrismou\StreamSeal\Psr7;

use Chrismou\StreamSeal\Exception\DecryptionFailedException;
use Chrismou\StreamSeal\Exception\InvalidArgumentException;
use Chrismou\StreamSeal\Exception\InvalidKeyException;
use Chrismou\StreamSeal\Exception\StreamException;
use Chrismou\StreamSeal\Exception\StreamSealExceptionInterface;
use Chrismou\StreamSeal\StreamSeal;
use Psr\Http\Message\StreamInterface;
use RuntimeException;
use SensitiveParameter;
use Throwable;

/**
 * StreamSeal over PSR-7 streams. Requires psr/http-message to be installed.
 *
 * Both streams are used from their current position, so rewind the input first if it has been read.
 */
final readonly class Psr7StreamSeal
{
    public function __construct(private StreamSeal $seal = new StreamSeal())
    {
    }

    /**
     * Encrypt everything readable from $in and write the sealed stream to $out.
     *
     * @throws InvalidArgumentException when $in is not readable, $out is not writable, or they are the same stream
     * @throws InvalidKeyException when the key is the wrong length
     * @throws StreamException when $in cannot be read or $out cannot be fully written, or either stream throws
     */
    public function encrypt(StreamInterface $in, StreamInterface $out, #[SensitiveParameter] string $key): void
    {
        [$inResource, $outResource] = $this->wrap($in, $out);

        try {
            $this->seal->encrypt($inResource, $outResource, $key);
        } catch (RuntimeException $e) {
            throw self::fromStreamFailure($e);
        } finally {
            fclose($inResource);
            fclose($outResource);
        }
    }

    /**
     * Decrypt a sealed stream from $in, writing plaintext to $out.
     *
     * @throws InvalidArgumentException when $in is not readable, $out is not writable, or they are the same stream
     * @throws InvalidKeyException when the key is the wrong length
     * @throws DecryptionFailedException when the key is wrong or the stream is corrupt, truncated or has trailing data
     * @throws StreamException when $in cannot be read or $out cannot be fully written, or either stream throws
     */
    public function decrypt(StreamInterface $in, StreamInterface $out, #[SensitiveParameter] string $key): void
    {
        [$inResource, $outResource] = $this->wrap($in, $out);

        try {
            $this->seal->decrypt($inResource, $outResource, $key);
        } catch (RuntimeException $e) {
            throw self::fromStreamFailure($e);
        } finally {
            fclose($inResource);
            fclose($outResource);
        }
    }

    /**
     * Wrap both streams as resources, closing the first again if the second cannot be opened.
     *
     * @return array{resource, resource}
     *
     * @throws InvalidArgumentException
     * @throws StreamException
     */
    private function wrap(StreamInterface $in, StreamInterface $out): array
    {
        if (! $in->isReadable()) {
            throw new InvalidArgumentException('The input stream is not readable.');
        }

        if (! $out->isWritable()) {
            throw new InvalidArgumentException('The output stream is not writable.');
        }

        if ($in === $out) {
            throw new InvalidArgumentException('The input and output must be different streams.');
        }

        $inResource = Psr7StreamWrapper::resourceFor($in, 'rb');

        try {
            $outResource = Psr7StreamWrapper::resourceFor($out, 'wb');
        } catch (Throwable $e) {
            fclose($inResource);

            throw $e;
        }

        // Ask the PSR-7 stream for a whole sealed chunk per read instead of PHP's 8 KiB default.
        stream_set_chunk_size($inResource, $this->seal->chunkBytes + StreamSeal::TAG_BYTES);

        return [$inResource, $outResource];
    }

    /**
     * Pass the library's own exceptions through and wrap anything thrown by the PSR-7 streams themselves.
     */
    private static function fromStreamFailure(RuntimeException $e): RuntimeException
    {
        return $e instanceof StreamSealExceptionInterface ? $e : StreamException::fromPsr7Stream($e);
    }
}
