<?php

declare(strict_types=1);

namespace Chrismou\StreamSeal\Tests\Support;

/**
 * Stream wrapper that serves a fixed string one byte per read, to exercise short-read handling.
 * Usage: fopen(OneByteReadStreamWrapper::url($contents), 'rb').
 */
final class OneByteReadStreamWrapper
{
    public const PROTOCOL = 'onebyte';

    /** @var array<string, string> */
    private static array $contentsByPath = [];

    /** @var resource|null */
    public $context;

    private string $contents = '';

    private int $position = 0;

    public static function url(string $contents): string
    {
        self::register();

        $path = bin2hex(random_bytes(8));
        self::$contentsByPath[$path] = $contents;

        return self::PROTOCOL.'://'.$path;
    }

    public static function register(): void
    {
        if (! in_array(self::PROTOCOL, stream_get_wrappers(), true)) {
            stream_wrapper_register(self::PROTOCOL, self::class);
        }
    }

    public function stream_open(string $path, string $mode, int $options, ?string &$openedPath): bool
    {
        $key = substr($path, strlen(self::PROTOCOL) + 3);

        if (! isset(self::$contentsByPath[$key])) {
            return false;
        }

        $this->contents = self::$contentsByPath[$key];

        return true;
    }

    public function stream_read(int $count): string
    {
        $byte = substr($this->contents, $this->position, 1);
        $this->position += strlen($byte);

        return $byte;
    }

    public function stream_eof(): bool
    {
        return $this->position >= strlen($this->contents);
    }

    /**
     * @return array<int|string, int>
     */
    public function stream_stat(): array
    {
        return ['size' => strlen($this->contents)];
    }
}
