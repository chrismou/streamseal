<?php

declare(strict_types=1);

namespace Chrismou\StreamSeal\Exception;

use InvalidArgumentException as BaseInvalidArgumentException;

/**
 * Thrown when an argument other than the key is unusable: a bad chunk size, a length no sealed stream
 * can have, or a stream argument that is not an open, distinct stream resource.
 */
final class InvalidArgumentException extends BaseInvalidArgumentException implements StreamSealExceptionInterface
{
}
