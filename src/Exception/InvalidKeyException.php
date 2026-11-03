<?php

declare(strict_types=1);

namespace Chrismou\StreamSeal\Exception;

use InvalidArgumentException;

/**
 * Thrown when a key is not exactly StreamSeal::KEY_BYTES long.
 */
final class InvalidKeyException extends InvalidArgumentException implements StreamSealExceptionInterface
{
    public static function wrongLength(int $expected, int $actual): self
    {
        return new self(sprintf('Key must be exactly %d bytes, %d given.', $expected, $actual));
    }
}
