<?php

declare(strict_types=1);

namespace Chrismou\StreamSeal\Exception;

use RuntimeException;

/**
 * Thrown when the input stream cannot be read or the output stream cannot be fully written.
 */
final class StreamException extends RuntimeException implements StreamSealExceptionInterface
{
    public static function readFailed(): self
    {
        return new self('Reading from the input stream failed.');
    }

    public static function shortWrite(int $expected, int $written): self
    {
        return new self(sprintf('Short write to the output stream: expected %d bytes, wrote %d.', $expected, $written));
    }
}
