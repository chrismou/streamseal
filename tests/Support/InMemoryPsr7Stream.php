<?php

declare(strict_types=1);

namespace Chrismou\StreamSeal\Tests\Support;

use Psr\Http\Message\StreamInterface;
use RuntimeException;
use Throwable;

/**
 * Minimal string-backed PSR-7 stream with no underlying resource, so the adapter is proven
 * to work without detach(). The optional constructor arguments make it misbehave in the ways
 * real implementations can: short reads, an eof() that only turns true after an empty read,
 * no seeking, reads or writes that throw, and writes that report fewer bytes than given.
 */
final class InMemoryPsr7Stream implements StreamInterface
{
    private int $position = 0;

    private bool $sawEmptyRead = false;

    public int $largestReadRequest = 0;

    public function __construct(
        private string $buffer = '',
        private readonly bool $readable = true,
        private readonly bool $writable = true,
        private readonly int $maxReadBytes = PHP_INT_MAX,
        private readonly bool $lazyEof = false,
        private readonly bool $seekable = true,
        private readonly ?Throwable $readFailure = null,
        private readonly ?Throwable $writeFailure = null,
        private readonly ?int $reportedWriteBytes = null,
    ) {
    }

    public function __toString(): string
    {
        return $this->buffer;
    }

    public function close(): void
    {
    }

    public function detach()
    {
        return null;
    }

    public function getSize(): int
    {
        return strlen($this->buffer);
    }

    public function tell(): int
    {
        return $this->position;
    }

    public function eof(): bool
    {
        if ($this->lazyEof) {
            return $this->sawEmptyRead;
        }

        return $this->position >= strlen($this->buffer);
    }

    public function isSeekable(): bool
    {
        return $this->seekable;
    }

    public function seek(int $offset, int $whence = SEEK_SET): void
    {
        if (! $this->seekable) {
            throw new RuntimeException('Stream is not seekable.');
        }

        $this->position = match ($whence) {
            SEEK_SET => $offset,
            SEEK_CUR => $this->position + $offset,
            SEEK_END => strlen($this->buffer) + $offset,
            default => throw new RuntimeException('Unknown whence.'),
        };
    }

    public function rewind(): void
    {
        $this->seek(0);
    }

    public function isWritable(): bool
    {
        return $this->writable;
    }

    public function write(string $string): int
    {
        if (! $this->writable) {
            throw new RuntimeException('Stream is not writable.');
        }

        if ($this->writeFailure !== null) {
            throw $this->writeFailure;
        }

        if ($this->reportedWriteBytes !== null) {
            return $this->reportedWriteBytes;
        }

        if ($this->position === strlen($this->buffer)) {
            $this->buffer .= $string;
        } else {
            $this->buffer = substr($this->buffer, 0, $this->position).$string;
        }

        $this->position += strlen($string);

        return strlen($string);
    }

    public function isReadable(): bool
    {
        return $this->readable;
    }

    public function read(int $length): string
    {
        if (! $this->readable) {
            throw new RuntimeException('Stream is not readable.');
        }

        if ($this->readFailure !== null) {
            throw $this->readFailure;
        }

        $this->largestReadRequest = max($this->largestReadRequest, $length);

        $chunk = substr($this->buffer, $this->position, min($length, $this->maxReadBytes));
        $this->position += strlen($chunk);
        $this->sawEmptyRead = $this->sawEmptyRead || $chunk === '';

        return $chunk;
    }

    public function getContents(): string
    {
        return $this->read(strlen($this->buffer) - $this->position);
    }

    public function getMetadata(?string $key = null): mixed
    {
        return $key === null ? [] : null;
    }
}
