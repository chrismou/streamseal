<?php

declare(strict_types=1);

namespace Chrismou\StreamSeal\Tests\Unit\Psr7;

use Chrismou\StreamSeal\Exception\DecryptionFailedException;
use Chrismou\StreamSeal\Exception\InvalidArgumentException;
use Chrismou\StreamSeal\Exception\InvalidKeyException;
use Chrismou\StreamSeal\Exception\StreamException;
use Chrismou\StreamSeal\Psr7\Psr7StreamSeal;
use Chrismou\StreamSeal\Psr7\Psr7StreamWrapper;
use Chrismou\StreamSeal\StreamSeal;
use Chrismou\StreamSeal\Tests\Support\InMemoryPsr7Stream;
use Chrismou\StreamSeal\Tests\Support\Streams;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class Psr7StreamSealTest extends TestCase
{
    #[Test]
    public function testRoundTripsThroughPsr7StreamsWithoutAnUnderlyingResource(): void
    {
        $seal = new Psr7StreamSeal(new StreamSeal(10));
        $key = StreamSeal::generateKey();
        $plaintext = random_bytes(45);

        $sealed = new InMemoryPsr7Stream();
        $seal->encrypt(new InMemoryPsr7Stream($plaintext), $sealed, $key);

        self::assertSame((new StreamSeal(10))->sealedLength(45), $sealed->getSize());

        $sealed->rewind();
        $plain = new InMemoryPsr7Stream();
        $seal->decrypt($sealed, $plain, $key);

        self::assertSame($plaintext, (string) $plain);
    }

    #[Test]
    public function testRoundTripsThroughAwkwardPsr7Streams(): void
    {
        $seal = new Psr7StreamSeal(new StreamSeal(10));
        $key = StreamSeal::generateKey();
        $plaintext = random_bytes(45);

        $sealed = new InMemoryPsr7Stream(seekable: false);
        $seal->encrypt(new InMemoryPsr7Stream($plaintext, maxReadBytes: 3, lazyEof: true, seekable: false), $sealed, $key);

        $plain = new InMemoryPsr7Stream();
        $seal->decrypt(new InMemoryPsr7Stream((string) $sealed, maxReadBytes: 3, lazyEof: true, seekable: false), $plain, $key);

        self::assertSame($plaintext, (string) $plain);
    }

    #[Test]
    public function testReadsAWholeChunkFromThePsr7StreamAtATime(): void
    {
        $in = new InMemoryPsr7Stream(random_bytes(20_000));

        (new Psr7StreamSeal())->encrypt($in, new InMemoryPsr7Stream(), StreamSeal::generateKey());

        self::assertGreaterThanOrEqual(20_000, $in->largestReadRequest);
    }

    #[Test]
    public function testOutputIsInterchangeableWithTheResourceApi(): void
    {
        $key = StreamSeal::generateKey();
        $plaintext = 'sealed by psr-7, opened by resource';

        $sealed = new InMemoryPsr7Stream();
        (new Psr7StreamSeal())->encrypt(new InMemoryPsr7Stream($plaintext), $sealed, $key);

        $out = Streams::sink();
        (new StreamSeal())->decrypt(Streams::of((string) $sealed), $out, $key);

        self::assertSame($plaintext, Streams::contents($out));
    }

    #[Test]
    public function testDecryptionFailuresPropagate(): void
    {
        $seal = new Psr7StreamSeal();

        $this->expectException(DecryptionFailedException::class);

        $seal->decrypt(new InMemoryPsr7Stream('not a sealed stream'), new InMemoryPsr7Stream(), StreamSeal::generateKey());
    }

    #[Test]
    public function testRejectsAKeyOfTheWrongLength(): void
    {
        $this->expectException(InvalidKeyException::class);

        (new Psr7StreamSeal())->encrypt(new InMemoryPsr7Stream('x'), new InMemoryPsr7Stream(), 'short');
    }

    #[Test]
    public function testEncryptRejectsAnUnreadableInput(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('not readable');

        (new Psr7StreamSeal())->encrypt(new InMemoryPsr7Stream('x', readable: false), new InMemoryPsr7Stream(), StreamSeal::generateKey());
    }

    #[Test]
    public function testEncryptRejectsAnUnwritableOutput(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('not writable');

        (new Psr7StreamSeal())->encrypt(new InMemoryPsr7Stream('x'), new InMemoryPsr7Stream(writable: false), StreamSeal::generateKey());
    }

    #[Test]
    public function testDecryptRejectsAnUnreadableInput(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('not readable');

        (new Psr7StreamSeal())->decrypt(new InMemoryPsr7Stream('x', readable: false), new InMemoryPsr7Stream(), StreamSeal::generateKey());
    }

    #[Test]
    public function testDecryptRejectsAnUnwritableOutput(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('not writable');

        (new Psr7StreamSeal())->decrypt(new InMemoryPsr7Stream('x'), new InMemoryPsr7Stream(writable: false), StreamSeal::generateKey());
    }

    #[Test]
    public function testRejectsTheSameStreamForInputAndOutput(): void
    {
        $stream = new InMemoryPsr7Stream('x');

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('different streams');

        (new Psr7StreamSeal())->encrypt($stream, $stream, StreamSeal::generateKey());
    }

    #[Test]
    public function testAShortWriteToThePsr7OutputThrows(): void
    {
        $this->expectException(StreamException::class);
        $this->expectExceptionMessage('Short write');

        (new Psr7StreamSeal())->encrypt(new InMemoryPsr7Stream('x'), new InMemoryPsr7Stream(reportedWriteBytes: 0), StreamSeal::generateKey());
    }

    #[Test]
    public function testAnExceptionFromThePsr7InputIsWrappedAndTheResourcesAreClosed(): void
    {
        $failure = new RuntimeException('disk on fire');
        $openStreams = count(get_resources('stream'));

        try {
            (new Psr7StreamSeal())->encrypt(new InMemoryPsr7Stream('x', readFailure: $failure), new InMemoryPsr7Stream(), StreamSeal::generateKey());
            self::fail('Expected the read failure to propagate.');
        } catch (StreamException $e) {
            self::assertSame($failure, $e->getPrevious());
            self::assertStringContainsString('disk on fire', $e->getMessage());
        }

        self::assertCount($openStreams, get_resources('stream'));
    }

    #[Test]
    public function testAnExceptionFromThePsr7OutputIsWrapped(): void
    {
        $failure = new RuntimeException('quota exceeded');

        $this->expectException(StreamException::class);
        $this->expectExceptionMessage('quota exceeded');

        (new Psr7StreamSeal())->encrypt(new InMemoryPsr7Stream('x'), new InMemoryPsr7Stream(writeFailure: $failure), StreamSeal::generateKey());
    }

    #[Test]
    public function testTheWrapperRefusesToOpenWithoutAStreamInItsContext(): void
    {
        fclose(Psr7StreamWrapper::resourceFor(new InMemoryPsr7Stream(), 'rb'));

        self::assertFalse(@fopen(Psr7StreamWrapper::PROTOCOL.'://stream', 'rb'));

        $context = stream_context_create([Psr7StreamWrapper::PROTOCOL => ['stream' => 'not a stream']]);

        self::assertFalse(@fopen(Psr7StreamWrapper::PROTOCOL.'://stream', 'rb', false, $context));
    }

    #[Test]
    public function testAForeignWrapperOnTheSameProtocolIsDetected(): void
    {
        if (in_array(Psr7StreamWrapper::PROTOCOL, stream_get_wrappers(), true)) {
            stream_wrapper_unregister(Psr7StreamWrapper::PROTOCOL);
        }

        stream_wrapper_register(Psr7StreamWrapper::PROTOCOL, ForeignStreamWrapper::class);

        try {
            (new Psr7StreamSeal())->encrypt(new InMemoryPsr7Stream('x'), new InMemoryPsr7Stream(), StreamSeal::generateKey());
            self::fail('Expected the foreign wrapper to be detected.');
        } catch (StreamException $e) {
            self::assertStringContainsString('another stream wrapper', $e->getMessage());
        } finally {
            stream_wrapper_unregister(Psr7StreamWrapper::PROTOCOL);
        }
    }
}

/**
 * Stands in for an unrelated library that happens to register the same protocol name.
 */
final class ForeignStreamWrapper
{
    /** @var resource|null */
    public $context;

    public function stream_open(string $path, string $mode, int $options, ?string &$openedPath): bool
    {
        return true;
    }

    public function stream_read(int $count): string
    {
        return '';
    }

    public function stream_write(string $data): int
    {
        return strlen($data);
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
