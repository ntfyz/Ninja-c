<?php
declare(strict_types=1);

return [
    // Prefer a path outside public_html, for example /home/CPANEL_USER/ninja-data/keys.sqlite3.
    'database' => dirname(__DIR__) . '/private/keys.sqlite3',
    // Generate with: php -r "echo password_hash('CHANGE_ME', PASSWORD_DEFAULT), PHP_EOL;"
    'admin_password_hash' => '$2y$10$REPLACE_WITH_PASSWORD_HASH',
    'session_name' => 'ninja_key_admin',
];
