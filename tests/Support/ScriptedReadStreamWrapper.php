<?php

declare(strict_types=1);

namespace Chrismou\StreamSeal\Tests\Support;

/**
 * Stream wrapper that answers each read from a script of responses: a string of bytes, or false for a
 * failed read. Once the script runs out it keeps returning an empty string, and reports end of file
 * only if asked to, so stalled, interrupted and failed reads can all be simulated.
 * Usage: fopen(ScriptedReadStreamWrapper::url(['abc', '', 'def'], eofWhenExhausted: true), 'rb').
 */
final class ScriptedReadStreamWrapper
{
    public const PROTOCOL = 'scripted';

    /** @var array<string, array{list<string|false>, bool}> */
    private static array $scriptsByPath = [];

    /** @var resource|null */
    public $context;

    /** @var list<string|false> */
    private array $responses = [];

    private bool $eofWhenExhausted = true;

    /**
     * @param  list<string|false>  $responses
     */
    public static function url(array $responses, bool $eofWhenExhausted): string
    {
        if (! in_array(self::PROTOCOL, stream_get_wrappers(), true)) {
            stream_wrapper_register(self::PROTOCOL, self::class);
        }

        $path = bin2hex(random_bytes(8));
        self::$scriptsByPath[$path] = [$responses, $eofWhenExhausted];

        return self::PROTOCOL.'://'.$path;
    }

    public function stream_open(string $path, string $mode, int $options, ?string &$openedPath): bool
    {
        $key = substr($path, strlen(self::PROTOCOL) + 3);

        if (! isset(self::$scriptsByPath[$key])) {
            return false;
        }

        [$this->responses, $this->eofWhenExhausted] = self::$scriptsByPath[$key];

        return true;
    }

    public function stream_read(int $count): string|false
    {
        return array_shift($this->responses) ?? '';
    }

    public function stream_eof(): bool
    {
        return $this->eofWhenExhausted && $this->responses === [];
    }

    /**
     * @return array<int|string, int>
     */
    public function stream_stat(): array
    {
        return [];
    }
}
