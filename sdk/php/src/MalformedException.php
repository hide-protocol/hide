<?php

declare(strict_types=1);

namespace HideProtocol;

/**
 * The bytes did not decode at all.
 *
 * A subclass of AuthenticationException so that code which only cares that
 * something failed is unaffected, while a caller that must tell corruption
 * from forgery can catch this specifically.
 */
final class MalformedException extends AuthenticationException
{
}
