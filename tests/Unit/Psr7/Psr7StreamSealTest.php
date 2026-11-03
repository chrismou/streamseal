<?php

declare(strict_types=1);

namespace Chrismou\StreamSeal\Tests\Unit\Psr7;

use Chrismou\StreamSeal\Exception\DecryptionFailedException;
use Chrismou\StreamSeal\Psr7\Psr7StreamSeal;
use Chrismou\StreamSeal\StreamSeal;
use Chrismou\StreamSeal\Tests\Support\InMemoryPsr7Stream;
use Chrismou\StreamSeal\Tests\Support\Streams;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

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
    public function testRejectsAnUnreadableInput(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('not readable');

        (new Psr7StreamSeal())->encrypt(new InMemoryPsr7Stream('x', readable: false), new InMemoryPsr7Stream(), StreamSeal::generateKey());
    }

    #[Test]
    public function testRejectsAnUnwritableOutput(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('not writable');

        (new Psr7StreamSeal())->encrypt(new InMemoryPsr7Stream('x'), new InMemoryPsr7Stream(writable: false), StreamSeal::generateKey());
    }
}
