<?php
declare(strict_types=1);

return [
    // Prefer a path outside public_html, for example /home/CPANEL_USER/ninja-data/keys.sqlite3.
    'database' => dirname(__DIR__) . '/private/keys.sqlite3',
    // SHA-256 of a long random admin password. Generate with: echo -n 'PASSWORD' | sha256sum
    'admin_password_sha256' => 'REPLACE_WITH_64_HEX_SHA256',
    'session_name' => 'ninja_key_admin',
];
