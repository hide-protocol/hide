<?php

declare(strict_types=1);

namespace HideProtocol;

/** This challenge was already answered. Almost certainly a replay. */
class ChallengeReplayedException extends HideException
{
}
