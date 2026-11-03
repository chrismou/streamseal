<?php

declare(strict_types=1);

namespace Chrismou\StreamSeal\Psr7;

use Chrismou\StreamSeal\Exception\StreamException;
use Psr\Http\Message\StreamInterface;

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
     *
     * @throws StreamException when the wrapper cannot be registered or the protocol belongs to another wrapper
     */
    public static function resourceFor(StreamInterface $stream, string $mode)
    {
        if (! in_array(self::PROTOCOL, stream_get_wrappers(), true) && ! stream_wrapper_register(self::PROTOCOL, self::class)) {
            throw StreamException::wrapFailed(sprintf('the %s:// wrapper could not be registered', self::PROTOCOL));
        }

        $context = stream_context_create([self::PROTOCOL => ['stream' => $stream]]);
        $resource = @fopen(self::PROTOCOL.'://stream', $mode, false, $context);

        if ($resource === false) {
            throw StreamException::wrapFailed('fopen failed');
        }

        // Another wrapper registered under our protocol would silently read and write something else entirely.
        if (! (stream_get_meta_data($resource)['wrapper_data'] ?? null) instanceof self) {
            fclose($resource);

            throw StreamException::wrapFailed(sprintf('the %s:// protocol is registered to another stream wrapper', self::PROTOCOL));
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
     * Nothing is buffered here, so there is never anything to flush.
     */
    public function stream_flush(): bool
    {
        return true;
    }

    /**
     * The PSR-7 stream stays open for its owner; only the wrapping resource goes away.
     */
    public function stream_close(): void
    {
    }

    /**
     * @return array<int|string, int>
     */
    public function stream_stat(): array
    {
        return [];
    }
}
