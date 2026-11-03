<?php

declare(strict_types=1);

namespace Chrismou\StreamSeal\Psr7;

use Psr\Http\Message\StreamInterface;
use RuntimeException;

/**
 * Exposes a PSR-7 stream as a native PHP stream resource so StreamSeal can read or write it.
 * Works with any StreamInterface implementation, resource-backed or not.
 */
final class Psr7StreamWrapper
{
    public const PROTOCOL = 'streamseal-psr7';

    /** @var resource|null */
    public $context;

    private StreamInterface $stream;

    /**
     * Open a resource over the given PSR-7 stream. Closing the resource does not close the stream.
     *
     * @param  'rb'|'wb'  $mode
     * @return resource
     */
    public static function resourceFor(StreamInterface $stream, string $mode)
    {
        if (! in_array(self::PROTOCOL, stream_get_wrappers(), true)) {
            stream_wrapper_register(self::PROTOCOL, self::class);
        }

        $context = stream_context_create([self::PROTOCOL => ['stream' => $stream]]);
        $resource = fopen(self::PROTOCOL.'://stream', $mode, false, $context);

        if ($resource === false) {
            throw new RuntimeException('Could not wrap the PSR-7 stream as a resource.');
        }

        return $resource;
    }

    public function stream_open(string $path, string $mode, int $options, ?string &$openedPath): bool
    {
        if ($this->context === null) {
            return false;
        }

        $stream = stream_context_get_options($this->context)[self::PROTOCOL]['stream'] ?? null;

        if (! $stream instanceof StreamInterface) {
            return false;
        }

        $this->stream = $stream;

        return true;
    }

    public function stream_read(int $count): string
    {
        return $this->stream->read($count);
    }

    public function stream_write(string $data): int
    {
        return $this->stream->write($data);
    }

    public function stream_eof(): bool
    {
        return $this->stream->eof();
    }

    /**
     * @return array<int|string, int>
     */
    public function stream_stat(): array
    {
        return [];
    }
}
