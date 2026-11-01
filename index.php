<?php
declare(strict_types=1);

define('FILEBIN_DATA_DIR', getenv('FILEBIN_DATA_DIR') ?: __DIR__ . '/data');
define('FILEBIN_DB', getenv('FILEBIN_DB') ?: FILEBIN_DATA_DIR . '/filebin.sqlite');
define('FILEBIN_SECRET_FILE', FILEBIN_DATA_DIR . '/secret.key');

$maxUploadEnv = getenv('FILEBIN_MAX_BYTES');
define('FILEBIN_MAX_BYTES', ($maxUploadEnv !== false && (int)$maxUploadEnv > 0) ? (int)$maxUploadEnv : 50 * 1024 * 1024);

define('FILEBIN_TITLE', 'Secure PHP SQLite Filebin');

ini_set('display_errors', '0');
error_reporting(E_ALL);
ini_set('log_errors', '1');
date_default_timezone_set('UTC');

function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

function base_url(): string
{
    $scheme = 'http';

    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        $scheme = 'https';
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
        $scheme = 'https';
    }

    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $script = $_SERVER['SCRIPT_NAME'] ?? '/filebin.php';

    return $scheme . '://' . $host . $script;
}

function fail(string $message, int $code = 400): void
{
    if (!headers_sent()) {
        http_response_code($code);
        header('Content-Type: text/html; charset=utf-8');
        header('X-Content-Type-Options: nosniff');
    }

    echo '<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
<style>
body{font-family:system-ui,Arial,sans-serif;max-width:720px;margin:40px auto;padding:0 16px}
</style>
</head>
<body>
<h1>Error</h1>
<p>' . e($message) . '</p>
<p><a href="' . e(base_url()) . '">Back</a></p>
</body>
</html>';

    exit;
}

if (!extension_loaded('pdo_sqlite')) {
    fail('The pdo_sqlite extension is required.', 500);
}

if (!function_exists('sodium_crypto_secretbox')) {
    fail('The sodium extension is required.', 500);
}

if (!is_dir(FILEBIN_DATA_DIR)) {
    @mkdir(FILEBIN_DATA_DIR, 0700, true);
}

if (!is_dir(FILEBIN_DATA_DIR)) {
    fail('Cannot create data directory. Check permissions.', 500);
}

$htaccess = FILEBIN_DATA_DIR . '/.htaccess';
if (!file_exists($htaccess)) {
    @file_put_contents(
        $htaccess,
        "<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Order deny,allow\n    Deny from all\n</IfModule>\n"
    );
}

function db(): PDO
{
    static $pdo = null;

    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $pdo = new PDO('sqlite:' . FILEBIN_DB, null, null, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);

    $pdo->exec('PRAGMA journal_mode=WAL');
    $pdo->exec('PRAGMA synchronous=NORMAL');
    $pdo->exec('PRAGMA temp_store=MEMORY');
    $pdo->exec('PRAGMA busy_timeout=5000');
    $pdo->exec('PRAGMA secure_delete=ON');

    $pdo->exec('
        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            original_name TEXT NOT NULL,
            mime TEXT NOT NULL,
            size INTEGER NOT NULL,
            ciphertext BLOB NOT NULL,
            nonce BLOB NOT NULL,
            wrapped_key BLOB NOT NULL,
            app_nonce BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER,
            password_hash TEXT,
            delete_token_hash TEXT NOT NULL,
            downloads INTEGER NOT NULL DEFAULT 0
        )
    ');

    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_files_expires ON files(expires_at)');

    return $pdo;
}

function app_key(): string
{
    static $key = null;

    if ($key !== null) {
        return $key;
    }

    $secret = getenv('FILEBIN_SECRET');

    if ($secret === false || $secret === '') {
        if (is_file(FILEBIN_SECRET_FILE)) {
            $secret = file_get_contents(FILEBIN_SECRET_FILE);
        } else {
            $secret = base64_encode(random_bytes(32));

            if (@file_put_contents(FILEBIN_SECRET_FILE, $secret, LOCK_EX) === false) {
                fail('Cannot create secret key file. Check data directory permissions.', 500);
            }

            @chmod(FILEBIN_SECRET_FILE, 0600);
        }
    }

    if ($secret === false || $secret === '') {
        fail('Application secret is empty.', 500);
    }

    $keyLength = defined('SODIUM_CRYPTO_SECRETBOX_KEYBYTES')
        ? SODIUM_CRYPTO_SECRETBOX_KEYBYTES
        : 32;

    $key = sodium_crypto_generichash(
        (string)$secret,
        'filebin-master-key-v1',
        $keyLength
    );

    sodium_memzero($secret);

    return $key;
}

function random_id(int $bytes = 12): string
{
    return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
}

function str_limit(string $value, int $limit): string
{
    if (function_exists('mb_substr')) {
        return mb_substr($value, 0, $limit, 'UTF-8');
    }

    return substr($value, 0, $limit);
}

function safe_filename(string $name): string
{
    $name = str_replace('\\', '/', $name);
    $name = basename($name);
    $name = trim($name);

    if ($name === '' || $name === '.' || $name === '..') {
        return 'download.bin';
    }

    $clean = preg_replace('/[^\p{L}\p{N}\._\- ]/u', '_', $name);

    if (!is_string($clean) || trim($clean) === '') {
        $clean = preg_replace('/[^A-Za-z0-9._-]/', '_', $name);

        if (!is_string($clean) || trim($clean) === '') {
            $clean = 'download.bin';
        }
    }

    return str_limit(trim($clean), 255);
}

function detect_mime(string $path, string $fallback): string
{
    if (function_exists('finfo_open')) {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);

        if ($finfo) {
            $mime = finfo_file($finfo, $path);
            finfo_close($finfo);

            if (is_string($mime) && $mime !== '') {
                return $mime;
            }
        }
    }

    return $fallback !== '' ? $fallback : 'application/octet-stream';
}

function parse_expiry(): ?int
{
    $mode = (string)($_POST['expiry'] ?? 'never');

    if ($mode === 'never') {
        return null;
    }

    if ($mode === 'custom') {
        $minutes = (int)($_POST['custom_minutes'] ?? 0);

        if ($minutes <= 0) {
            return null;
        }

        if ($minutes > 525600) {
            fail('Custom expiry is too large.', 400);
        }

        return time() + ($minutes * 60);
    }

    $seconds = (int)$mode;

    if ($seconds <= 0) {
        return null;
    }

    if ($seconds > 31536000) {
        fail('Expiry is too large.', 400);
    }

    return time() + $seconds;
}

function purge_expired(): void
{
    $stmt = db()->prepare('DELETE FROM files WHERE expires_at IS NOT NULL AND expires_at <= :now');
    $stmt->bindValue(':now', time(), PDO::PARAM_INT);
    $stmt->execute();
}

function find_file(string $id): ?array
{
    if ($id === '') {
        return null;
    }

    $stmt = db()->prepare('SELECT * FROM files WHERE id = ?');
    $stmt->execute([$id]);

    $row = $stmt->fetch();

    if (!$row) {
        return null;
    }

    foreach (['ciphertext', 'nonce', 'wrapped_key', 'app_nonce'] as $col) {
        if (isset($row[$col]) && is_resource($row[$col])) {
            $row[$col] = (string)stream_get_contents($row[$col]);
        }
    }

    return $row;
}

function is_expired(array $row): bool
{
    return $row['expires_at'] !== null && (int)$row['expires_at'] <= time();
}

function decrypt_row(array $row): string
{
    $appKey = app_key();

    $wrappedKey = $row['wrapped_key'] ?? null;
    $appNonce   = $row['app_nonce'] ?? null;
    $cipher     = $row['ciphertext'] ?? null;
    $nonce      = $row['nonce'] ?? null;

    if (is_resource($wrappedKey)) {
        $wrappedKey = stream_get_contents($wrappedKey);
    }

    if (is_resource($appNonce)) {
        $appNonce = stream_get_contents($appNonce);
    }

    if (is_resource($cipher)) {
        $cipher = stream_get_contents($cipher);
    }

    if (is_resource($nonce)) {
        $nonce = stream_get_contents($nonce);
    }

    if (!is_string($wrappedKey) || !is_string($appNonce) || !is_string($cipher) || !is_string($nonce)) {
        fail('Invalid encrypted payload.', 500);
    }

    $fileKey = sodium_crypto_secretbox_open($wrappedKey, $appNonce, $appKey);

    if ($fileKey === false) {
        fail('Unable to decrypt file key.', 500);
    }

    $plain = sodium_crypto_secretbox_open($cipher, $nonce, $fileKey);
    sodium_memzero($fileKey);

    if ($plain === false) {
        fail('Unable to decrypt file data.', 500);
    }

    return $plain;
}

function page_header(string $title): void
{
    if (!headers_sent()) {
        header('Content-Type: text/html; charset=utf-8');
        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: no-referrer');
        header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
    }

    echo '<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>' . e($title) . '</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#f6f7f9;color:#111;margin:0;padding:24px}
.card{max-width:760px;margin:0 auto;background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:24px}
h1{margin-top:0;font-size:1.4rem}
label{display:block;margin:12px 0}
input,select,button{width:100%;box-sizing:border-box;padding:10px;border:1px solid #d1d5db;border-radius:8px;font:inherit}
button{width:auto;margin-top:16px;background:#111;color:#fff;border:0;padding:10px 18px;cursor:pointer}
button:hover{background:#333}
.muted,.links p{color:#555;font-size:.95rem}
.links input{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.85rem;background:#f9fafb}
.error{color:#b91c1c;background:#fee2e2;border:1px solid #fecaca;padding:10px;border-radius:8px}
.badge{display:inline-block;background:#eef2ff;color:#3730a3;border-radius:999px;padding:2px 10px;font-size:.85rem;margin-right:6px}
</style>
</head>
<body>';
}

function page_footer(): void
{
    echo '</body></html>';
}

function render_home(): void
{
    page_header('Upload');

    $maxMb = round(FILEBIN_MAX_BYTES / 1048576, 1);

    ?>
    <div class="card">
        <h1><?= e(FILEBIN_TITLE) ?></h1>
        <p class="muted">Upload a file. It will be encrypted and stored in a SQLite blob.</p>

        <form method="post" action="?action=upload" enctype="multipart/form-data">
            <input type="hidden" name="MAX_FILE_SIZE" value="<?= (int)FILEBIN_MAX_BYTES ?>">

            <label>
                File
                <input type="file" name="file" required>
            </label>

            <label>
                Optional download password
                <input type="password" name="password" minlength="8" autocomplete="new-password" placeholder="Leave empty for no password">
            </label>

            <label>
                Expiry
                <select name="expiry">
                    <option value="never">Never</option>
                    <option value="300">5 minutes</option>
                    <option value="3600">1 hour</option>
                    <option value="86400">1 day</option>
                    <option value="604800">7 days</option>
                    <option value="2592000">30 days</option>
                    <option value="custom">Custom minutes</option>
                </select>
            </label>

            <label>
                Custom minutes, used only when expiry is set to Custom minutes
                <input type="number" name="custom_minutes" min="1" max="525600" value="60">
            </label>

            <button type="submit">Encrypt and upload</button>
        </form>

        <p class="muted">
            Max upload size: <?= e((string)$maxMb) ?> MB.<br>
            Delete links are capability URLs. Keep them secret.
        </p>
    </div>
    <?php

    page_footer();
}

function render_upload_success(
    string $id,
    string $deleteToken,
    string $filename,
    ?int $expiresAt,
    bool $hasPassword
): void {
    $downloadUrl = base_url() . '?action=view&id=' . rawurlencode($id);
    $deleteUrl = base_url() . '?action=remove&id=' . rawurlencode($id) . '&token=' . rawurlencode($deleteToken);

    page_header('Uploaded');

    ?>
    <div class="card">
        <h1>File uploaded</h1>

        <p>
            <span class="badge"><?= e($filename) ?></span>
            <?php if ($hasPassword): ?>
                <span class="badge">Password required</span>
            <?php endif; ?>
            <span class="badge">
                <?= $expiresAt === null ? 'No expiry' : 'Expires ' . e(date('Y-m-d H:i T', $expiresAt)) ?>
            </span>
        </p>

        <div class="links">
            <label>
                Download link
                <input readonly value="<?= e($downloadUrl) ?>">
            </label>
            <p>
                <a href="<?= e($downloadUrl) ?>">Open download page</a>
            </p>

            <label>
                Delete link
                <input readonly value="<?= e($deleteUrl) ?>">
            </label>
            <p>
                <a href="<?= e($deleteUrl) ?>">Open delete confirmation</a>
            </p>

            <p class="muted">
                The delete link opens a confirmation page before removing the file.<br>
                Save it now. It is not shown again.
            </p>
        </div>

        <p>
            <a href="<?= e(base_url()) ?>">Upload another file</a>
        </p>
    </div>
    <?php

    page_footer();
}

function render_password_form(string $id, ?string $error): void
{
    page_header('Password required');

    ?>
    <div class="card">
        <h1>Password required</h1>

        <?php if ($error !== null): ?>
            <p class="error"><?= e($error) ?></p>
        <?php endif; ?>

        <form method="post" action="?action=view&id=<?= e($id) ?>">
            <label>
                Password
                <input type="password" name="password" required autofocus>
            </label>

            <button type="submit">Unlock and download</button>
        </form>

        <p class="muted">Use HTTPS in production.</p>
    </div>
    <?php

    page_footer();
}

function render_remove_confirm(string $filename, string $id, string $token): void
{
    page_header('Confirm deletion');

    ?>
    <div class="card">
        <h1>Delete file</h1>

        <p>
            Delete <span class="badge"><?= e($filename) ?></span> permanently?
        </p>

        <form method="post" action="?action=remove">
            <input type="hidden" name="id" value="<?= e($id) ?>">
            <input type="hidden" name="token" value="<?= e($token) ?>">
            <input type="hidden" name="confirm" value="1">

            <button type="submit">Yes, delete permanently</button>
        </form>

        <p class="muted">This cannot be undone.</p>
    </div>
    <?php

    page_footer();
}

function render_deleted(): void
{
    page_header('Deleted');

    ?>
    <div class="card">
        <h1>Deleted</h1>
        <p>The file was removed.</p>
        <p><a href="<?= e(base_url()) ?>">Back</a></p>
    </div>
    <?php

    page_footer();
}

function deliver_file(array $row): void
{
    $plain = decrypt_row($row);

    $stmt = db()->prepare('UPDATE files SET downloads = downloads + 1 WHERE id = ?');
    $stmt->execute([$row['id']]);

    while (ob_get_level() > 0) {
        @ob_end_clean();
    }

    $original = (string)($row['original_name'] ?? 'download.bin');

    $ascii = preg_replace('/[^\x20-\x7e]/', '_', $original);
    if (!is_string($ascii) || $ascii === '') {
        $ascii = 'download.bin';
    }

    $ascii = str_replace('"', '', $ascii);

    if (!headers_sent()) {
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . $ascii . '"; filename*=UTF-8\'\'' . rawurlencode($original));
        header('Content-Length: ' . strlen($plain));
        header('Cache-Control: no-store, max-age=0');
        header('X-Content-Type-Options: nosniff');
    }

    echo $plain;

    if (function_exists('sodium_memzero')) {
        sodium_memzero($plain);
    }

    exit;
}

function handle_upload(): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        fail('Method not allowed.', 405);
    }

    if (empty($_FILES) && empty($_POST)) {
        fail('Upload failed. Check post_max_size and upload_max_filesize.', 413);
    }

    if (empty($_FILES['file']) || !is_array($_FILES['file'])) {
        fail('No file selected.');
    }

    $file = $_FILES['file'];

    $error = (int)($file['error'] ?? UPLOAD_ERR_NO_FILE);
    if ($error !== UPLOAD_ERR_OK) {
        fail('Upload error code ' . $error . '.', 400);
    }

    if (!is_uploaded_file((string)$file['tmp_name'])) {
        fail('Invalid uploaded file.');
    }

    if (!isset($file['size']) || (int)$file['size'] <= 0) {
        fail('Empty file.');
    }

    if ((int)$file['size'] > FILEBIN_MAX_BYTES) {
        fail('File exceeds maximum size.');
    }

    $originalName = safe_filename((string)($file['name'] ?? ''));
    $mime = detect_mime((string)$file['tmp_name'], (string)($file['type'] ?? ''));

    $plain = file_get_contents((string)$file['tmp_name']);

    if ($plain === false) {
        fail('Could not read uploaded file.');
    }

    $originalSize = strlen($plain);

    if ($originalSize <= 0) {
        fail('Empty file.');
    }

    if ($originalSize > FILEBIN_MAX_BYTES) {
        fail('File exceeds maximum size.');
    }

    $password = (string)($_POST['password'] ?? '');
    $passwordHash = null;

    if ($password !== '') {
        if (strlen($password) < 8) {
            fail('Password must be at least 8 characters.');
        }

        $passwordHash = password_hash($password, PASSWORD_DEFAULT);

        if ($passwordHash === false) {
            fail('Password hashing failed.', 500);
        }
    }

    $expiresAt = parse_expiry();

    $fileKey = sodium_crypto_secretbox_keygen();
    $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

    $cipher = sodium_crypto_secretbox($plain, $nonce, $fileKey);
    sodium_memzero($plain);

    $appNonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $wrappedKey = sodium_crypto_secretbox($fileKey, $appNonce, app_key());
    sodium_memzero($fileKey);

    $id = random_id(12);
    $deleteToken = bin2hex(random_bytes(32));
    $deleteHash = hash('sha256', $deleteToken);

    $stmt = db()->prepare('
        INSERT INTO files (
            id,
            original_name,
            mime,
            size,
            ciphertext,
            nonce,
            wrapped_key,
            app_nonce,
            created_at,
            expires_at,
            password_hash,
            delete_token_hash,
            downloads
        ) VALUES (
            :id,
            :original_name,
            :mime,
            :size,
            :ciphertext,
            :nonce,
            :wrapped_key,
            :app_nonce,
            :created_at,
            :expires_at,
            :password_hash,
            :delete_token_hash,
            0
        )
    ');

    $stmt->bindValue(':id', $id, PDO::PARAM_STR);
    $stmt->bindValue(':original_name', $originalName, PDO::PARAM_STR);
    $stmt->bindValue(':mime', $mime, PDO::PARAM_STR);
    $stmt->bindValue(':size', $originalSize, PDO::PARAM_INT);
    $stmt->bindValue(':ciphertext', $cipher, PDO::PARAM_LOB);
    $stmt->bindValue(':nonce', $nonce, PDO::PARAM_LOB);
    $stmt->bindValue(':wrapped_key', $wrappedKey, PDO::PARAM_LOB);
    $stmt->bindValue(':app_nonce', $appNonce, PDO::PARAM_LOB);
    $stmt->bindValue(':created_at', time(), PDO::PARAM_INT);

    if ($expiresAt === null) {
        $stmt->bindValue(':expires_at', null, PDO::PARAM_NULL);
    } else {
        $stmt->bindValue(':expires_at', $expiresAt, PDO::PARAM_INT);
    }

    if ($passwordHash === null) {
        $stmt->bindValue(':password_hash', null, PDO::PARAM_NULL);
    } else {
        $stmt->bindValue(':password_hash', $passwordHash, PDO::PARAM_STR);
    }

    $stmt->bindValue(':delete_token_hash', $deleteHash, PDO::PARAM_STR);

    $stmt->execute();

    render_upload_success($id, $deleteToken, $originalName, $expiresAt, $passwordHash !== null);
}

function handle_view(): void
{
    $id = (string)($_GET['id'] ?? '');

    $row = find_file($id);

    if ($row === null || is_expired($row)) {
        fail('File not found or expired.', 404);
    }

    if ($row['password_hash'] !== null) {
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $password = (string)($_POST['password'] ?? '');

            if ($password !== '' && password_verify($password, (string)$row['password_hash'])) {
                deliver_file($row);
            }

            render_password_form($id, 'Incorrect password.');
            return;
        }

        render_password_form($id, null);
        return;
    }

    deliver_file($row);
}

function handle_remove(): void
{
    $id = (string)($_GET['id'] ?? $_POST['id'] ?? '');
    $token = (string)($_GET['token'] ?? $_POST['token'] ?? '');

    $row = find_file($id);

    if ($row === null || $token === '') {
        fail('Delete link not found or invalid.', 404);
    }

    $expected = (string)($row['delete_token_hash'] ?? '');
    $actual = hash('sha256', $token);

    if (!hash_equals($expected, $actual)) {
        fail('Delete link not found or invalid.', 404);
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['confirm'])) {
        $stmt = db()->prepare('DELETE FROM files WHERE id = ?');
        $stmt->execute([$id]);

        render_deleted();
        return;
    }

    render_remove_confirm((string)$row['original_name'], $id, $token);
}

try {
    if (isset($_SERVER['REQUEST_URI'])) {
        $path = (string)(parse_url((string)$_SERVER['REQUEST_URI'], PHP_URL_PATH) ?: '');

        if (preg_match('/\.(sqlite|sqlite3|key)$/i', $path)) {
            http_response_code(404);
            exit;
        }
    }

    db();
    purge_expired();

    $action = $_GET['action'] ?? $_POST['action'] ?? 'home';

    switch ($action) {
        case 'upload':
            handle_upload();
            break;

        case 'view':
            handle_view();
            break;

        case 'remove':
            handle_remove();
            break;

        default:
            render_home();
            break;
    }
} catch (Throwable $e) {
    error_log($e->getMessage());
    fail('Internal server error.', 500);
}