<?php

declare(strict_types=1);

namespace Chrismou\StreamSeal\Psr7;

use Chrismou\StreamSeal\Exception\DecryptionFailedException;
use Chrismou\StreamSeal\Exception\InvalidKeyException;
use Chrismou\StreamSeal\Exception\StreamException;
use Chrismou\StreamSeal\StreamSeal;
use InvalidArgumentException;
use Psr\Http\Message\StreamInterface;
use SensitiveParameter;

/**
 * StreamSeal over PSR-7 streams. Requires psr/http-message to be installed.
 */
final readonly class Psr7StreamSeal
{
    public function __construct(private StreamSeal $seal = new StreamSeal())
    {
    }

    /**
     * Encrypt everything readable from $in and write the sealed stream to $out.
     *
     * @throws InvalidArgumentException when $in is not readable or $out is not writable
     * @throws InvalidKeyException when the key is the wrong length
     * @throws StreamException when $in cannot be read or $out cannot be fully written
     */
    public function encrypt(StreamInterface $in, StreamInterface $out, #[SensitiveParameter] string $key): void
    {
        [$inResource, $outResource] = self::wrap($in, $out);

        try {
            $this->seal->encrypt($inResource, $outResource, $key);
        } finally {
            fclose($inResource);
            fclose($outResource);
        }
    }

    /**
     * Decrypt a sealed stream from $in, writing plaintext to $out.
     *
     * @throws InvalidArgumentException when $in is not readable or $out is not writable
     * @throws InvalidKeyException when the key is the wrong length
     * @throws DecryptionFailedException when the key is wrong or the stream is corrupt, truncated or has trailing data
     * @throws StreamException when $in cannot be read or $out cannot be fully written
     */
    public function decrypt(StreamInterface $in, StreamInterface $out, #[SensitiveParameter] string $key): void
    {
        [$inResource, $outResource] = self::wrap($in, $out);

        try {
            $this->seal->decrypt($inResource, $outResource, $key);
        } finally {
            fclose($inResource);
            fclose($outResource);
        }
    }

    /**
     * @return array{resource, resource}
     */
    private static function wrap(StreamInterface $in, StreamInterface $out): array
    {
        if (! $in->isReadable()) {
            throw new InvalidArgumentException('The input stream is not readable.');
        }

        if (! $out->isWritable()) {
            throw new InvalidArgumentException('The output stream is not writable.');
        }

        return [
            Psr7StreamWrapper::resourceFor($in, 'rb'),
            Psr7StreamWrapper::resourceFor($out, 'wb'),
        ];
    }
}
