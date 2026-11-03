<?php

declare(strict_types=1);

namespace Chrismou\StreamSeal\Tests\Support;

/**
 * Stream wrapper whose writes always fail, to exercise short-write handling.
 * Usage: fopen(UnwritableStreamWrapper::url(), 'wb').
 */
final class UnwritableStreamWrapper
{
    public const PROTOCOL = 'unwritable';

    /** @var resource|null */
    public $context;

    public static function url(): string
    {
        if (! in_array(self::PROTOCOL, stream_get_wrappers(), true)) {
            stream_wrapper_register(self::PROTOCOL, self::class);
        }

        return self::PROTOCOL.'://sink';
    }

    public function stream_open(string $path, string $mode, int $options, ?string &$openedPath): bool
    {
        return true;
    }

    public function stream_write(string $data): int
    {
        return 0;
    }

    public function stream_eof(): bool
    {
        return true;
    }

    /**
     * @return array<int|string, int>
     */
    public function stream_stat(): array
    {
        return [];
    }
}
