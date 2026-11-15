<?php

declare(strict_types=1);

namespace HideProtocol;

/**
 * The challenge names an audience this verifier does not answer to.
 *
 * An answer minted for another service is refused, so a challenge relayed from
 * elsewhere cannot be answered here.
 */
class ChallengeAudienceException extends HideException
{
}
