<?php

declare(strict_types=1);

namespace Chrismou\StreamSeal\Exception;

use RuntimeException;
use Throwable;

/**
 * Thrown when a sealed stream cannot be decrypted: wrong key, tampering, truncation or trailing data.
 * Plaintext chunks decrypted before the failure have already been written to the output stream.
 */
final class DecryptionFailedException extends RuntimeException implements StreamSealExceptionInterface
{
    public static function missingHeader(): self
    {
        return new self('Sealed stream is missing its header.');
    }

    public static function invalidHeader(?Throwable $previous = null): self
    {
        return new self('Sealed stream header is invalid.', previous: $previous);
    }

    public static function corruptChunk(?Throwable $previous = null): self
    {
        return new self('Sealed stream could not be decrypted: wrong key or corrupt chunk.', previous: $previous);
    }

    public static function trailingData(): self
    {
        return new self('Sealed stream has data after its final chunk.');
    }

    public static function truncated(): self
    {
        return new self('Sealed stream is truncated.');
    }
}
