<?php

declare(strict_types=1);

namespace Chrismou\StreamSeal\Tests\Support;

use Psr\Http\Message\StreamInterface;
use RuntimeException;

/**
 * Minimal string-backed PSR-7 stream with no underlying resource, so the adapter is proven
 * to work without detach().
 */
final class InMemoryPsr7Stream implements StreamInterface
{
    private int $position = 0;

    public function __construct(
        private string $buffer = '',
        private readonly bool $readable = true,
        private readonly bool $writable = true,
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
        return $this->position >= strlen($this->buffer);
    }

    public function isSeekable(): bool
    {
        return true;
    }

    public function seek(int $offset, int $whence = SEEK_SET): void
    {
        $this->position = match ($whence) {
            SEEK_SET => $offset,
            SEEK_CUR => $this->position + $offset,
            SEEK_END => strlen($this->buffer) + $offset,
            default => throw new RuntimeException('Unknown whence.'),
        };
    }

    public function rewind(): void
    {
        $this->position = 0;
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

        $this->buffer = substr($this->buffer, 0, $this->position).$string;
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

        $chunk = substr($this->buffer, $this->position, $length);
        $this->position += strlen($chunk);

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
