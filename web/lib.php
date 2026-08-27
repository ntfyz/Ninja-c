<?php
declare(strict_types=1);

function ninja_config(): array {
    $path = __DIR__ . '/config.php';
    if (!is_file($path)) {
        throw new RuntimeException('Copy config.example.php to config.php and configure it.');
    }
    return require $path;
}

function ninja_db(): PDO {
    static $db = null;
    if ($db instanceof PDO) return $db;
    $path = (string)ninja_config()['database'];
    $directory = dirname($path);
    if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
        throw new RuntimeException('Cannot create database directory.');
    }
    $db = new PDO('sqlite:' . $path, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $db->exec('PRAGMA journal_mode=WAL');
    $db->exec('PRAGMA busy_timeout=5000');
    $db->exec('CREATE TABLE IF NOT EXISTS license_keys (
        key_name TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        hwid TEXT NULL,
        expires_at INTEGER NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )');
    return $db;
}

function ninja_json(int $status, array $payload): never {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    exit;
}

function ninja_random_key(): string {
    $raw = strtoupper(bin2hex(random_bytes(12)));
    return 'NINJA-' . implode('-', str_split($raw, 6));
}

function ninja_start_admin_session(): void {
    $config = ninja_config();
    session_name((string)$config['session_name']);
    session_set_cookie_params([
        'httponly' => true, 'secure' => true, 'samesite' => 'Strict', 'path' => '/',
    ]);
    session_start();
}

function ninja_csrf(): string {
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(24));
    return (string)$_SESSION['csrf'];
}

function ninja_require_csrf(): void {
    $value = (string)($_POST['csrf'] ?? '');
    if (!hash_equals(ninja_csrf(), $value)) throw new RuntimeException('Invalid request token.');
}
