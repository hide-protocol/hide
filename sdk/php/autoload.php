<?php

/**
 * A PSR-4 autoloader for HideProtocol\, so the SDK and its tests run without
 * composer install. Real consumers use vendor/autoload.php instead.
 */

declare(strict_types=1);

spl_autoload_register(static function (string $class): void {
    $prefix = 'HideProtocol\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }

    $relative = str_replace('\\', DIRECTORY_SEPARATOR, substr($class, strlen($prefix)));
    $file = __DIR__ . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . $relative . '.php';
    if (is_file($file)) {
        require $file;
    }
});
