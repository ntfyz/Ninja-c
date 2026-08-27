<?php
declare(strict_types=1);
require dirname(__DIR__) . '/lib.php';
ninja_start_admin_session();
$config = ninja_config();
$error = '';
if (isset($_POST['login'])) {
    if (password_verify((string)($_POST['password'] ?? ''), (string)$config['admin_password_hash'])) {
        session_regenerate_id(true); $_SESSION['admin'] = true; header('Location: ./'); exit;
    }
    $error = 'Sai mật khẩu quản trị.';
}
if (isset($_GET['logout'])) { session_destroy(); header('Location: ./'); exit; }
if (empty($_SESSION['admin'])) {
?><!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Ninja Key</title>
<style>body{font:16px system-ui;background:#111;color:#eee;display:grid;place-items:center;height:90vh}form{background:#222;padding:28px;border-radius:14px}input,button{padding:12px;margin:5px;border-radius:8px;border:1px solid #555}button{cursor:pointer}</style>
<form method="post"><h2>Ninja Key Manager</h2><p style="color:#f77"><?=htmlspecialchars($error)?></p><input type="password" name="password" placeholder="Mật khẩu admin" required><button name="login">Đăng nhập</button></form><?php exit;
}
$db = ninja_db();
try {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['login'])) {
        ninja_require_csrf(); $action = (string)($_POST['action'] ?? ''); $key = trim((string)($_POST['key'] ?? ''));
        if ($action === 'create') {
            $key = $key !== '' ? $key : ninja_random_key(); $password = (string)($_POST['key_password'] ?? $key);
            $days = max(1, min(3650, (int)($_POST['days'] ?? 30))); $now = time();
            $q=$db->prepare('INSERT INTO license_keys VALUES(?,?,NULL,?,1,?,?) ON CONFLICT(key_name) DO UPDATE SET password_hash=excluded.password_hash,expires_at=excluded.expires_at,enabled=1,updated_at=excluded.updated_at');
            $q->execute([$key,password_hash($password,PASSWORD_DEFAULT),$now+$days*86400,$now,$now]);
            $_SESSION['created'] = "Key: $key | Password: $password";
        } elseif ($action === 'clear_hwid') { $q=$db->prepare('UPDATE license_keys SET hwid=NULL,updated_at=? WHERE key_name=?'); $q->execute([time(),$key]);
        } elseif ($action === 'toggle') { $q=$db->prepare('UPDATE license_keys SET enabled=1-enabled,updated_at=? WHERE key_name=?'); $q->execute([time(),$key]);
        } elseif ($action === 'extend') { $days=max(1,min(3650,(int)($_POST['days']??30))); $q=$db->prepare('UPDATE license_keys SET expires_at=max(expires_at,?)+?,updated_at=? WHERE key_name=?'); $q->execute([time(),$days*86400,time(),$key]);
        } elseif ($action === 'delete') { $q=$db->prepare('DELETE FROM license_keys WHERE key_name=?'); $q->execute([$key]); }
        header('Location: ./'); exit;
    }
} catch (Throwable $e) { $error = $e->getMessage(); }
$rows=$db->query('SELECT * FROM license_keys ORDER BY created_at DESC')->fetchAll(); $created=$_SESSION['created']??''; unset($_SESSION['created']);
?><!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Ninja Key Manager</title><style>body{font:14px system-ui;background:#101114;color:#eee;margin:24px}input,button{padding:8px;border-radius:6px;border:1px solid #555;background:#222;color:#fff}table{width:100%;border-collapse:collapse;margin-top:20px}th,td{padding:9px;border-bottom:1px solid #333;text-align:left}form.inline{display:inline}.ok{color:#7fda91}.bad{color:#ff8585}</style></head><body>
<a href="?logout=1" style="float:right;color:#aaa">Đăng xuất</a><h1>Ninja Key Manager</h1><p class="ok"><?=htmlspecialchars($created)?></p><p class="bad"><?=htmlspecialchars($error)?></p>
<form method="post"><input type="hidden" name="csrf" value="<?=ninja_csrf()?>"><input type="hidden" name="action" value="create"><input name="key" placeholder="Key (để trống = tự tạo)"><input name="key_password" placeholder="Password (để trống = key)"><input name="days" type="number" value="30" min="1" max="3650"><button>Tạo key</button></form>
<table><tr><th>Key</th><th>HWID</th><th>Hết hạn</th><th>Trạng thái</th><th>Quản lý</th></tr><?php foreach($rows as $r): ?><tr><td><?=htmlspecialchars($r['key_name'])?></td><td><?=htmlspecialchars($r['hwid']??'Chưa bind')?></td><td><?=date('Y-m-d H:i',(int)$r['expires_at'])?></td><td><?=$r['enabled']?'Bật':'Khóa'?></td><td><?php foreach(['clear_hwid'=>'Xóa HWID','toggle'=>'Bật/khóa','extend'=>'+30 ngày','delete'=>'Xóa'] as $a=>$label): ?><form class="inline" method="post"><input type="hidden" name="csrf" value="<?=ninja_csrf()?>"><input type="hidden" name="action" value="<?=$a?>"><input type="hidden" name="key" value="<?=htmlspecialchars($r['key_name'])?>"><?php if($a==='extend'):?><input type="hidden" name="days" value="30"><?php endif?><button><?=$label?></button></form><?php endforeach?></td></tr><?php endforeach?></table></body></html>
