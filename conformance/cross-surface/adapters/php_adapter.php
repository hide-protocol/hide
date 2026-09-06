<?php

declare(strict_types=1);

/**
 * Drives the PHP SDK for the cross-surface interop matrix. Two commands:
 *   php php_adapter.php encrypt <public-key> <plaintext> <out-container>
 *   php php_adapter.php decrypt <secret-key> <container> <out-plaintext>
 */

require __DIR__ . '/../../../sdk/php/autoload.php';

use HideProtocol\Hide;
use HideProtocol\SecretKey;

if ($argc < 5) {
    fwrite(STDERR, "usage: php_adapter.php encrypt|decrypt <key> <input> <output>\n");
    exit(2);
}

[, $command, $keyPath, $inputPath, $outputPath] = $argv;

$read = static function (string $path): string {
    $data = file_get_contents($path);
    if ($data === false) {
        fwrite(STDERR, "cannot read {$path}\n");
        exit(1);
    }

    return $data;
};

switch ($command) {
    case 'encrypt':
        file_put_contents(
            $outputPath,
            Hide::encrypt($read($inputPath), [$read($keyPath)], 'php.txt'),
        );
        break;
    case 'decrypt':
        $secret = SecretKey::open($read($keyPath));
        try {
            file_put_contents($outputPath, Hide::decrypt($read($inputPath), $secret)->plaintext);
        } finally {
            $secret->close();
        }
        break;
    default:
        fwrite(STDERR, "unknown command: {$command}\n");
        exit(2);
}
