<?php

declare(strict_types=1);

namespace Chrismou\StreamSeal\Exception;

use RuntimeException;
use Throwable;

/**
 * Thrown when the input stream cannot be read or the output stream cannot be fully written.
 */
final class StreamException extends RuntimeException implements StreamSealExceptionInterface
{
    public static function readFailed(?string $reason = null): self
    {
        return new self('Reading from the input stream failed'.self::because($reason));
    }

    public static function readStalled(): self
    {
        return new self(
            'The input stream returned no data before its end. Non-blocking and timed-out streams are not supported.'
        );
    }

    public static function shortWrite(int $expected, int $written, ?string $reason = null): self
    {
        return new self(sprintf(
            'Short write to the output stream: expected %d bytes, wrote %d%s',
            $expected,
            $written,
            self::because($reason),
        ));
    }

    public static function wrapFailed(string $reason): self
    {
        return new self(sprintf('Could not wrap the PSR-7 stream as a resource: %s.', $reason));
    }

    public static function fromPsr7Stream(Throwable $previous): self
    {
        return new self('The PSR-7 stream failed: '.$previous->getMessage(), previous: $previous);
    }

    private static function because(?string $reason): string
    {
        return $reason === null ? '.' : sprintf(' (%s).', $reason);
    }
}
