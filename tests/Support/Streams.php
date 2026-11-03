<?php

declare(strict_types=1);

namespace Chrismou\StreamSeal\Tests\Support;

use RuntimeException;

/**
 * In-memory stream helpers for tests.
 */
final class Streams
{
    /**
     * Open a readable in-memory stream positioned at the start of $contents.
     *
     * @return resource
     */
    public static function of(string $contents)
    {
        $stream = fopen('php://memory', 'w+b');

        if ($stream === false) {
            throw new RuntimeException('Could not open a memory stream.');
        }

        fwrite($stream, $contents);
        rewind($stream);

        return $stream;
    }

    /**
     * Open an empty writable in-memory stream.
     *
     * @return resource
     */
    public static function sink()
    {
        return self::of('');
    }

    /**
     * Everything written to the stream so far.
     *
     * @param  resource  $stream
     */
    public static function contents($stream): string
    {
        rewind($stream);
        $contents = stream_get_contents($stream);

        return $contents === false ? '' : $contents;
    }
}
