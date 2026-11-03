<?php

declare(strict_types=1);

namespace Chrismou\StreamSeal\Tests\Unit;

use Chrismou\StreamSeal\Exception\DecryptionFailedException;
use Chrismou\StreamSeal\Exception\InvalidArgumentException;
use Chrismou\StreamSeal\Exception\InvalidKeyException;
use Chrismou\StreamSeal\Exception\StreamException;
use Chrismou\StreamSeal\Exception\StreamSealExceptionInterface;
use Chrismou\StreamSeal\StreamSeal;
use Chrismou\StreamSeal\Tests\Support\OneByteReadStreamWrapper;
use Chrismou\StreamSeal\Tests\Support\ScriptedReadStreamWrapper;
use Chrismou\StreamSeal\Tests\Support\Streams;
use Chrismou\StreamSeal\Tests\Support\UnwritableStreamWrapper;
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

    /**
     * @return array<string, array{int}>
     */
    public static function fileLengths(): array
    {
        return [
            'empty' => [0],
            'exactly one chunk' => [10],
            'one byte over a chunk' => [11],
            'several chunks' => [25],
        ];
    }

    #[Test]
    #[DataProvider('fileLengths')]
    public function testRoundTripsThroughRealFiles(int $length): void
    {
        $seal = new StreamSeal(10);
        $key = StreamSeal::generateKey();
        $plaintext = $length > 0 ? random_bytes($length) : '';

        $in = self::file($plaintext);
        $sealed = self::file('');
        $seal->encrypt($in, $sealed, $key);

        self::assertSame($seal->sealedLength($length), ftell($sealed));

        rewind($sealed);
        $out = self::file('');
        $seal->decrypt($sealed, $out, $key);

        self::assertSame($plaintext, Streams::contents($out));
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

    /**
     * @return array<string, array{int, list<int>}>
     */
    public static function chunkTags(): array
    {
        $message = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
        $final = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL;

        return [
            'empty' => [0, [$final]],
            'partial chunk' => [4, [$final]],
            'exactly one chunk' => [10, [$final]],
            'exactly two chunks' => [20, [$message, $final]],
            'two chunks and a bit' => [21, [$message, $message, $final]],
        ];
    }

    /**
     * @param  list<int>  $expectedTags
     */
    #[Test]
    #[DataProvider('chunkTags')]
    public function testOnlyTheLastChunkCarriesTheFinalTag(int $length, array $expectedTags): void
    {
        $key = StreamSeal::generateKey();
        $sealed = self::encrypt(new StreamSeal(10), str_repeat('a', $length), $key);

        $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull(substr($sealed, 0, StreamSeal::HEADER_BYTES), $key);
        $tags = [];

        foreach (str_split(substr($sealed, StreamSeal::HEADER_BYTES), 10 + StreamSeal::TAG_BYTES) as $chunk) {
            $result = sodium_crypto_secretstream_xchacha20poly1305_pull($state, $chunk);
            self::assertNotFalse($result);
            $tags[] = $result[1];
        }

        self::assertSame($expectedTags, $tags);
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
    public function testAStreamWithOnlyAHeaderIsTruncated(): void
    {
        $seal = new StreamSeal(10);
        $key = StreamSeal::generateKey();
        $sealed = self::encrypt($seal, 'abc', $key);

        $this->expectException(DecryptionFailedException::class);
        $this->expectExceptionMessage('truncated');

        self::decrypt($seal, substr($sealed, 0, StreamSeal::HEADER_BYTES), $key);
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
    public function testTrailingDataAfterAFullFinalChunkFailsBeforeThatChunkIsWritten(): void
    {
        $seal = new StreamSeal(10);
        $key = StreamSeal::generateKey();
        $sealed = self::encrypt($seal, 'first-chunsecond-chu', $key);

        $out = Streams::sink();

        try {
            $seal->decrypt(Streams::of($sealed.'junk'), $out, $key);
            self::fail('Expected the trailing data to be rejected.');
        } catch (DecryptionFailedException $e) {
            self::assertStringContainsString('after its final chunk', $e->getMessage());
            self::assertSame('first-chun', Streams::contents($out));
        }
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
    public function testTrailingDataAfterAnEmptyPlaintextSealFails(): void
    {
        $seal = new StreamSeal(10);
        $key = StreamSeal::generateKey();
        $sealed = self::encrypt($seal, '', $key);

        $this->expectException(DecryptionFailedException::class);

        self::decrypt($seal, $sealed.'j', $key);
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

    /**
     * @return array<string, array{int}>
     */
    public static function wrongKeyLengths(): array
    {
        return ['empty' => [0], 'one short' => [31], 'one long' => [33]];
    }

    #[Test]
    #[DataProvider('wrongKeyLengths')]
    public function testEncryptRejectsAKeyOfTheWrongLength(int $length): void
    {
        $this->expectException(InvalidKeyException::class);

        (new StreamSeal())->encrypt(Streams::of('x'), Streams::sink(), str_repeat('k', $length));
    }

    #[Test]
    public function testDecryptRejectsAKeyOfTheWrongLengthBeforeReading(): void
    {
        $this->expectException(InvalidKeyException::class);

        (new StreamSeal())->decrypt(Streams::of(''), Streams::sink(), str_repeat('k', 33));
    }

    /**
     * @return array<string, array{int}>
     */
    public static function invalidChunkSizes(): array
    {
        return [
            'zero' => [0],
            'negative' => [-1],
            'over the maximum' => [StreamSeal::MAX_CHUNK_BYTES + 1],
            'absurd' => [PHP_INT_MAX],
        ];
    }

    #[Test]
    #[DataProvider('invalidChunkSizes')]
    public function testChunkSizeMustBeWithinBounds(int $chunkBytes): void
    {
        $this->expectException(InvalidArgumentException::class);

        new StreamSeal($chunkBytes);
    }

    #[Test]
    public function testTheLargestChunkSizeIsAccepted(): void
    {
        self::assertSame(StreamSeal::MAX_CHUNK_BYTES, (new StreamSeal(StreamSeal::MAX_CHUNK_BYTES))->chunkBytes);
    }

    /**
     * @return array<string, array{mixed}>
     */
    public static function notStreams(): array
    {
        $closed = fopen('php://memory', 'r');
        self::assertIsResource($closed);
        fclose($closed);

        return [
            'string' => ['php://memory'],
            'null' => [null],
            'closed resource' => [$closed],
            'resource that is not a stream' => [stream_context_create()],
        ];
    }

    #[Test]
    #[DataProvider('notStreams')]
    public function testRejectsAnInputThatIsNotAnOpenStreamBeforeWritingAnything(mixed $in): void
    {
        $out = Streams::sink();

        try {
            (new StreamSeal())->encrypt($in, $out, StreamSeal::generateKey());
            self::fail('Expected the input to be rejected.');
        } catch (InvalidArgumentException $e) {
            self::assertStringContainsString('input', $e->getMessage());
            self::assertSame('', Streams::contents($out));
        }
    }

    #[Test]
    #[DataProvider('notStreams')]
    public function testRejectsAnOutputThatIsNotAnOpenStream(mixed $out): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('output');

        (new StreamSeal())->decrypt(Streams::of('x'), $out, StreamSeal::generateKey());
    }

    #[Test]
    public function testRejectsTheSameResourceForInputAndOutput(): void
    {
        $stream = Streams::of('hello');

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('different streams');

        (new StreamSeal())->encrypt($stream, $stream, StreamSeal::generateKey());
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

    /**
     * @return array<string, array{int, int}>
     */
    public static function overflowingPlaintextLengths(): array
    {
        return [
            'maximum int' => [StreamSeal::DEFAULT_CHUNK_BYTES, PHP_INT_MAX],
            'just under the maximum' => [StreamSeal::DEFAULT_CHUNK_BYTES, PHP_INT_MAX - 100_000],
            'tag overhead alone overflows' => [1, intdiv(PHP_INT_MAX, 2)],
        ];
    }

    #[Test]
    #[DataProvider('overflowingPlaintextLengths')]
    public function testSealedLengthRejectsSizesThatOverflow(int $chunkBytes, int $plaintextLength): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('exceed');

        (new StreamSeal($chunkBytes))->sealedLength($plaintextLength);
    }

    #[Test]
    public function testLengthHelpersAcceptTheLargestRepresentableSizes(): void
    {
        // PHP_INT_MAX happens to be a valid sealed length at the largest chunk size, so it must round-trip.
        $seal = new StreamSeal(StreamSeal::MAX_CHUNK_BYTES);

        self::assertSame(PHP_INT_MAX, $seal->sealedLength($seal->plaintextLength(PHP_INT_MAX)));
    }

    /**
     * @return array<string, array{int}>
     */
    public static function impossibleSealedLengths(): array
    {
        $cases = [];

        // With 10-byte chunks a sealed chunk is 27 bytes; a last chunk of 1 to 16 bytes has no room for its tag.
        foreach ([27 + 1, 27 + 5, 27 + 16, 54 + 1, 54 + 9, 54 + 16] as $body) {
            $cases["body of $body bytes"] = [StreamSeal::HEADER_BYTES + $body];
        }

        return $cases;
    }

    #[Test]
    #[DataProvider('impossibleSealedLengths')]
    public function testPlaintextLengthRejectsLengthsNoSealedStreamCanHave(int $sealedLength): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('No sealed stream');

        (new StreamSeal(10))->plaintextLength($sealedLength);
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

    /**
     * @return array<string, array{list<string|false>, bool}>
     */
    public static function stalledReads(): array
    {
        return [
            'nothing more arrives but the stream is still open' => [['hello'], false],
            'an empty read in the middle of the input' => [['abcde', '', 'fghij'], true],
        ];
    }

    /**
     * @param  list<string|false>  $responses
     */
    #[Test]
    #[DataProvider('stalledReads')]
    public function testEncryptRefusesToTreatAStalledReadAsTheEndOfTheInput(array $responses, bool $eofWhenExhausted): void
    {
        $this->expectException(StreamException::class);
        $this->expectExceptionMessage('returned no data before its end');

        (new StreamSeal(10))->encrypt(self::open(ScriptedReadStreamWrapper::url($responses, $eofWhenExhausted)), Streams::sink(), StreamSeal::generateKey());
    }

    #[Test]
    public function testDecryptRefusesToTreatAStalledReadAsTheEndOfTheInput(): void
    {
        $key = StreamSeal::generateKey();
        $sealed = self::encrypt(new StreamSeal(10), 'hello', $key);

        $this->expectException(StreamException::class);
        $this->expectExceptionMessage('returned no data before its end');

        (new StreamSeal(10))->decrypt(self::open(ScriptedReadStreamWrapper::url([substr($sealed, 0, 30)], false)), Streams::sink(), $key);
    }

    #[Test]
    public function testAFailedReadThrows(): void
    {
        $this->expectException(StreamException::class);
        $this->expectExceptionMessage('Reading from the input stream failed');

        (new StreamSeal())->encrypt(self::open(ScriptedReadStreamWrapper::url([false], true)), Streams::sink(), StreamSeal::generateKey());
    }

    #[Test]
    public function testAFailedReadFromAFileThrowsWithoutANotice(): void
    {
        $writeOnly = self::file('', 'wb');

        $this->expectException(StreamException::class);
        $this->expectExceptionMessage('Reading from the input stream failed');

        (new StreamSeal())->encrypt($writeOnly, Streams::sink(), StreamSeal::generateKey());
    }

    #[Test]
    public function testAFailedWriteThrowsRatherThanSilentlyDroppingBytes(): void
    {
        $this->expectException(StreamException::class);
        $this->expectExceptionMessage('Short write');

        (new StreamSeal())->encrypt(Streams::of('x'), self::open(UnwritableStreamWrapper::url(), 'wb'), StreamSeal::generateKey());
    }

    #[Test]
    public function testAFailedWriteToAFileThrowsWithoutANotice(): void
    {
        $readOnly = self::file('', 'rb');

        $this->expectException(StreamException::class);
        $this->expectExceptionMessage('Short write');

        (new StreamSeal())->encrypt(Streams::of('x'), $readOnly, StreamSeal::generateKey());
    }

    #[Test]
    public function testEveryExceptionImplementsTheMarkerInterface(): void
    {
        self::assertInstanceOf(StreamSealExceptionInterface::class, DecryptionFailedException::truncated());
        self::assertInstanceOf(StreamSealExceptionInterface::class, InvalidKeyException::wrongLength(32, 1));
        self::assertInstanceOf(StreamSealExceptionInterface::class, StreamException::readFailed());
        self::assertInstanceOf(StreamSealExceptionInterface::class, StreamException::readStalled());
        self::assertInstanceOf(StreamSealExceptionInterface::class, new InvalidArgumentException('bad argument'));
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

    /**
     * A real temporary file holding $contents, reopened in $mode and positioned at the start.
     *
     * @return resource
     */
    private static function file(string $contents, string $mode = 'r+b')
    {
        $path = tempnam(sys_get_temp_dir(), 'streamseal');

        self::assertNotFalse($path);
        file_put_contents($path, $contents);
        register_shutdown_function(static fn () => @unlink($path));

        return self::open($path, $mode);
    }
}
