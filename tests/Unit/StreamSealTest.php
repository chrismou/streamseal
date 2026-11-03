<?php

declare(strict_types=1);

namespace Chrismou\StreamSeal\Tests\Unit;

use Chrismou\StreamSeal\Exception\DecryptionFailedException;
use Chrismou\StreamSeal\Exception\InvalidKeyException;
use Chrismou\StreamSeal\Exception\StreamException;
use Chrismou\StreamSeal\Exception\StreamSealExceptionInterface;
use Chrismou\StreamSeal\StreamSeal;
use Chrismou\StreamSeal\Tests\Support\OneByteReadStreamWrapper;
use Chrismou\StreamSeal\Tests\Support\Streams;
use Chrismou\StreamSeal\Tests\Support\UnwritableStreamWrapper;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class StreamSealTest extends TestCase
{
    // --- round trips ---

    /**
     * @return array<string, array{string, int}>
     */
    public static function plaintexts(): array
    {
        $chunk = StreamSeal::DEFAULT_CHUNK_BYTES;

        return [
            'small' => ['hello streams', $chunk],
            'exactly one chunk' => [str_repeat('a', $chunk), $chunk],
            'one byte over a chunk' => [str_repeat('b', $chunk + 1), $chunk],
            'several chunks' => [random_bytes($chunk * 2 + 123), $chunk],
            'empty' => ['', $chunk],
            'tiny chunks' => [random_bytes(100), 7],
            'single byte chunks' => ['abc', 1],
        ];
    }

    #[Test]
    #[DataProvider('plaintexts')]
    public function testRoundTripsThroughEncryptAndDecrypt(string $plaintext, int $chunkBytes): void
    {
        $seal = new StreamSeal($chunkBytes);
        $key = StreamSeal::generateKey();

        $sealed = self::encrypt($seal, $plaintext, $key);

        self::assertNotSame($plaintext, $sealed);
        self::assertSame($seal->sealedLength(strlen($plaintext)), strlen($sealed));
        self::assertSame(strlen($plaintext), $seal->plaintextLength(strlen($sealed)));
        self::assertSame($plaintext, self::decrypt($seal, $sealed, $key));
    }

    #[Test]
    public function testCiphertextHidesThePlaintextAndDiffersBetweenEncryptions(): void
    {
        $seal = new StreamSeal();
        $key = StreamSeal::generateKey();
        $plaintext = 'the same secret twice';

        $first = self::encrypt($seal, $plaintext, $key);
        $second = self::encrypt($seal, $plaintext, $key);

        self::assertStringNotContainsString($plaintext, $first);
        self::assertNotSame($first, $second);
    }

    #[Test]
    public function testGenerateKeyReturnsRandomKeysOfTheRightLength(): void
    {
        $first = StreamSeal::generateKey();
        $second = StreamSeal::generateKey();

        self::assertSame(StreamSeal::KEY_BYTES, strlen($first));
        self::assertSame(32, StreamSeal::KEY_BYTES);
        self::assertNotSame($first, $second);
    }

    #[Test]
    public function testSealedStreamLayoutIsHeaderThenTaggedChunks(): void
    {
        $seal = new StreamSeal(10);

        self::assertSame(24, StreamSeal::HEADER_BYTES);
        self::assertSame(17, StreamSeal::TAG_BYTES);
        self::assertSame(24 + 17, $seal->sealedLength(0));
        self::assertSame(24 + 10 + 17, $seal->sealedLength(10));
        self::assertSame(24 + 11 + 34, $seal->sealedLength(11));
        self::assertSame(0, $seal->plaintextLength(24 + 17));
        self::assertSame(11, $seal->plaintextLength(24 + 11 + 34));
    }

    // --- decryption failures ---

    #[Test]
    public function testDecryptingWithTheWrongKeyFails(): void
    {
        $seal = new StreamSeal();
        $sealed = self::encrypt($seal, 'secret', StreamSeal::generateKey());

        $this->expectException(DecryptionFailedException::class);
        $this->expectExceptionMessage('wrong key or corrupt chunk');

        self::decrypt($seal, $sealed, StreamSeal::generateKey());
    }

    #[Test]
    public function testATamperedChunkFails(): void
    {
        $seal = new StreamSeal();
        $key = StreamSeal::generateKey();
        $sealed = self::encrypt($seal, 'secret', $key);
        $sealed[StreamSeal::HEADER_BYTES + 2] = $sealed[StreamSeal::HEADER_BYTES + 2] === 'x' ? 'y' : 'x';

        $this->expectException(DecryptionFailedException::class);
        $this->expectExceptionMessage('corrupt chunk');

        self::decrypt($seal, $sealed, $key);
    }

    #[Test]
    public function testAStreamTruncatedOnAChunkBoundaryFails(): void
    {
        $seal = new StreamSeal(10);
        $key = StreamSeal::generateKey();
        $sealed = self::encrypt($seal, str_repeat('a', 25), $key);
        $truncated = substr($sealed, 0, StreamSeal::HEADER_BYTES + 2 * (10 + StreamSeal::TAG_BYTES));

        $this->expectException(DecryptionFailedException::class);
        $this->expectExceptionMessage('truncated');

        self::decrypt($seal, $truncated, $key);
    }

    #[Test]
    public function testAStreamTruncatedMidChunkFails(): void
    {
        $seal = new StreamSeal(10);
        $key = StreamSeal::generateKey();
        $sealed = self::encrypt($seal, str_repeat('a', 25), $key);

        $this->expectException(DecryptionFailedException::class);

        self::decrypt($seal, substr($sealed, 0, -3), $key);
    }

    #[Test]
    public function testAStreamTruncatedInsideTheFinalTagFails(): void
    {
        $seal = new StreamSeal(10);
        $key = StreamSeal::generateKey();
        $sealed = self::encrypt($seal, str_repeat('a', 25), $key);

        $this->expectException(DecryptionFailedException::class);

        self::decrypt($seal, substr($sealed, 0, -(StreamSeal::TAG_BYTES + 3)), $key);
    }

    #[Test]
    public function testTrailingDataAfterAFullFinalChunkFails(): void
    {
        $seal = new StreamSeal(10);
        $key = StreamSeal::generateKey();
        $sealed = self::encrypt($seal, str_repeat('a', 20), $key);

        $this->expectException(DecryptionFailedException::class);
        $this->expectExceptionMessage('after its final chunk');

        self::decrypt($seal, $sealed.'junk', $key);
    }

    #[Test]
    public function testTrailingDataAfterAPartialFinalChunkFails(): void
    {
        $seal = new StreamSeal(10);
        $key = StreamSeal::generateKey();
        $sealed = self::encrypt($seal, str_repeat('a', 15), $key);

        $this->expectException(DecryptionFailedException::class);
        $this->expectExceptionMessage('corrupt chunk');

        self::decrypt($seal, $sealed.'junk', $key);
    }

    #[Test]
    public function testAnEmptyOrHeaderlessStreamFails(): void
    {
        $seal = new StreamSeal();

        $this->expectException(DecryptionFailedException::class);
        $this->expectExceptionMessage('missing its header');

        self::decrypt($seal, 'too short', StreamSeal::generateKey());
    }

    #[Test]
    public function testDecryptingWithADifferentChunkSizeFails(): void
    {
        $key = StreamSeal::generateKey();
        $sealed = self::encrypt(new StreamSeal(10), str_repeat('a', 25), $key);

        $this->expectException(DecryptionFailedException::class);

        self::decrypt(new StreamSeal(20), $sealed, $key);
    }

    #[Test]
    public function testChunksBeforeAFailureHaveAlreadyBeenWritten(): void
    {
        $seal = new StreamSeal(10);
        $key = StreamSeal::generateKey();
        $sealed = self::encrypt($seal, 'first-chunksecond-chunk', $key);
        $tamperedOffset = StreamSeal::HEADER_BYTES + 10 + StreamSeal::TAG_BYTES + 1;
        $sealed[$tamperedOffset] = $sealed[$tamperedOffset] === 'x' ? 'y' : 'x';

        $out = Streams::sink();

        try {
            $seal->decrypt(Streams::of($sealed), $out, $key);
            self::fail('Expected decryption to fail.');
        } catch (DecryptionFailedException) {
            self::assertSame('first-chun', Streams::contents($out));
        }
    }

    // --- argument validation ---

    #[Test]
    public function testEncryptRejectsAKeyOfTheWrongLength(): void
    {
        $this->expectException(InvalidKeyException::class);

        (new StreamSeal())->encrypt(Streams::of('x'), Streams::sink(), 'short');
    }

    #[Test]
    public function testDecryptRejectsAKeyOfTheWrongLengthBeforeReading(): void
    {
        $this->expectException(InvalidKeyException::class);

        (new StreamSeal())->decrypt(Streams::of(''), Streams::sink(), str_repeat('k', 33));
    }

    #[Test]
    public function testChunkSizeMustBePositive(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new StreamSeal(0);
    }

    #[Test]
    public function testLengthHelpersRejectImpossibleSizes(): void
    {
        $seal = new StreamSeal();

        try {
            $seal->sealedLength(-1);
            self::fail('Expected a negative plaintext length to be rejected.');
        } catch (InvalidArgumentException) {
        }

        $this->expectException(InvalidArgumentException::class);
        $seal->plaintextLength(StreamSeal::HEADER_BYTES + StreamSeal::TAG_BYTES - 1);
    }

    // --- stream behaviour ---

    #[Test]
    public function testShortReadsAreToleratedOnBothSides(): void
    {
        $seal = new StreamSeal(10);
        $key = StreamSeal::generateKey();
        $plaintext = random_bytes(45);

        $sealedOut = Streams::sink();
        $seal->encrypt(self::open(OneByteReadStreamWrapper::url($plaintext)), $sealedOut, $key);
        $sealed = Streams::contents($sealedOut);

        self::assertSame($seal->sealedLength(45), strlen($sealed));

        $plainOut = Streams::sink();
        $seal->decrypt(self::open(OneByteReadStreamWrapper::url($sealed)), $plainOut, $key);

        self::assertSame($plaintext, Streams::contents($plainOut));
    }

    #[Test]
    public function testAFailedWriteThrowsRatherThanSilentlyDroppingBytes(): void
    {
        $this->expectException(StreamException::class);
        $this->expectExceptionMessage('Short write');

        (new StreamSeal())->encrypt(Streams::of('x'), self::open(UnwritableStreamWrapper::url(), 'wb'), StreamSeal::generateKey());
    }

    #[Test]
    public function testEveryExceptionImplementsTheMarkerInterface(): void
    {
        self::assertInstanceOf(StreamSealExceptionInterface::class, DecryptionFailedException::truncated());
        self::assertInstanceOf(StreamSealExceptionInterface::class, InvalidKeyException::wrongLength(32, 1));
        self::assertInstanceOf(StreamSealExceptionInterface::class, StreamException::readFailed());
    }

    // --- helpers ---

    private static function encrypt(StreamSeal $seal, string $plaintext, string $key): string
    {
        $out = Streams::sink();
        $seal->encrypt(Streams::of($plaintext), $out, $key);

        return Streams::contents($out);
    }

    private static function decrypt(StreamSeal $seal, string $sealed, string $key): string
    {
        $out = Streams::sink();
        $seal->decrypt(Streams::of($sealed), $out, $key);

        return Streams::contents($out);
    }

    /**
     * @return resource
     */
    private static function open(string $url, string $mode = 'rb')
    {
        $stream = fopen($url, $mode);

        self::assertIsResource($stream);

        return $stream;
    }
}
