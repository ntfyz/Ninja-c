<?php
declare(strict_types=1);
require dirname(__DIR__, 5) . '/lib.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') ninja_json(405, ['ok' => false, 'code' => 'method_not_allowed']);
if ((int)($_SERVER['CONTENT_LENGTH'] ?? 0) > 16384) ninja_json(413, ['ok' => false, 'code' => 'request_too_large']);

try {
    $input = json_decode((string)file_get_contents('php://input'), true, 16, JSON_THROW_ON_ERROR);
} catch (Throwable $ignored) {
    ninja_json(400, ['ok' => false, 'code' => 'malformed_request']);
}
$username = trim((string)($input['username'] ?? ''));
$password = (string)($input['password'] ?? '');
$hwid = strtolower((string)($input['device_id'] ?? ''));
if ($username === '' || $password === '') ninja_json(400, ['ok' => false, 'code' => 'malformed_credentials']);
if (!preg_match('/^[0-9a-f]{64}$/', $hwid)) ninja_json(400, ['ok' => false, 'code' => 'device_id_unavailable']);

$db = ninja_db();
$db->beginTransaction();
try {
    $query = $db->prepare('SELECT * FROM license_keys WHERE key_name = ?');
    $query->execute([$username]);
    $row = $query->fetch();
    $now = time();
    if (!$row || !password_verify($password, (string)$row['password_hash'])) {
        $db->rollBack(); ninja_json(401, ['ok' => false, 'code' => 'invalid_credentials']);
    }
    if (!(int)$row['enabled']) { $db->rollBack(); ninja_json(403, ['ok' => false, 'code' => 'key_disabled']); }
    if ((int)$row['expires_at'] <= $now) { $db->rollBack(); ninja_json(403, ['ok' => false, 'code' => 'key_expired']); }
    if ($row['hwid'] !== null && !hash_equals((string)$row['hwid'], $hwid)) {
        $db->rollBack(); ninja_json(403, ['ok' => false, 'code' => 'device_mismatch']);
    }
    if ($row['hwid'] === null) {
        $update = $db->prepare('UPDATE license_keys SET hwid = ?, updated_at = ? WHERE key_name = ?');
        $update->execute([$hwid, $now, $username]);
    }
    $db->commit();
    $generation = random_int(1, PHP_INT_MAX);
    ninja_json(200, [
        'ok' => true, 'scope' => 'authenticated', 'expires_at' => (int)$row['expires_at'],
        'remaining_seconds' => (int)$row['expires_at'] - $now,
        'generation' => $generation, 'device_id' => $hwid,
    ]);
} catch (Throwable $ignored) {
    if ($db->inTransaction()) $db->rollBack();
    ninja_json(500, ['ok' => false, 'code' => 'server_error']);
}
