<?php
declare(strict_types=1);

/**
 * =================================================================================
 * Soap CMS - All-In-One Admin Panel & Public Site Renderer
 * =================================================================================
 *
 * This single file provides:
 * 1. A secure, multi-level admin panel to manage "Soaps".
 * 2. For each soap, sub-panels to manage Cast, Episodes, News, and Settings.
 * 3. A public-facing renderer to display the soap's website.
 *
 * --- USAGE ---
 * - Admin Panel: your-script.php
 * - Public Site: your-script.php?view=public&soap_id=the-soap-id
 *
 * --- FOLDERS REQUIRED ---
 * - data/ (writable)
 * - data/users.json
 * - data/soaps.json
 * - uploads/ (writable)
 */

// ========== ROUTER: Decide whether to show Admin or Public view ==========
if (isset($_GET['view']) && $_GET['view'] === 'public') {
    // ========== PUBLIC SITE RENDERER ==========
    define('DS', DIRECTORY_SEPARATOR);
    $soap_id = preg_replace('/[^a-z0-9_-]/i', '', $_GET['soap_id'] ?? 'default');
    $data_path = __DIR__ . DS . 'data' . DS . $soap_id;

    function read_public_json(string $path, array $default = []): array {
        return file_exists($path) ? json_decode(file_get_contents($path), true) ?? $default : $default;
    }
    
    $soaps_data = read_public_json(__DIR__ . DS . 'data' . DS . 'soaps.json');
    $main_soap_info = [];
    foreach ($soaps_data['soaps'] ?? [] as $s) {
        if ($s['id'] === $soap_id) {
            $main_soap_info = $s;
            break;
        }
    }

    $settings = read_public_json($data_path . DS . 'settings.json');
    $cast = read_public_json($data_path . DS . 'cast.json', ['cast' => []])['cast'];
    $episodes = read_public_json($data_path . DS . 'episodes.json', ['episodes' => []])['episodes'];
    $news = read_public_json($data_path . DS . 'news.json', ['news' => []])['news'];

    $primary_color = htmlspecialchars($settings['theme']['primary_color'] ?? '#1a202c');
    $accent_color = htmlspecialchars($settings['theme']['accent_color'] ?? '#2eaadc');
    $font = htmlspecialchars($settings['theme']['font'] ?? 'Open Sans');
    $font_url = 'https://fonts.googleapis.com/css2?family=' . urlencode($font) . ':wght@400;700&display=swap';
    $site_title = htmlspecialchars($settings['site_title'] ?? $main_soap_info['name'] ?? 'Soap Opera');
    $tagline = htmlspecialchars($settings['tagline'] ?? 'Welcome');
    $description = htmlspecialchars($settings['description'] ?? '');
    $logo = htmlspecialchars($main_soap_info['logo'] ?? '');
    $banner = htmlspecialchars($settings['banner_image'] ?? '');
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title><?= $site_title ?></title>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="<?= $font_url ?>" rel="stylesheet">
        <style>
            :root {
                --primary-color: <?= $primary_color ?>;
                --accent-color: <?= $accent_color ?>;
                --font-family: '<?= $font ?>', sans-serif;
                --text-color: #f7fafc;
                --heading-color: #ffffff;
                --bg-color-light: rgba(255, 255, 255, 0.05);
                --bg-color-dark: rgba(0, 0, 0, 0.2);
            }
            body { margin: 0; font-family: var(--font-family); background-color: var(--primary-color); color: var(--text-color); line-height: 1.6; }
            .container { max-width: 1100px; margin: 0 auto; padding: 20px; }
            header { background: var(--bg-color-dark); padding: 20px 0; text-align: center; border-bottom: 2px solid var(--accent-color); }
            header img.logo { max-height: 80px; margin-bottom: 10px; }
            header h1 { color: var(--heading-color); margin: 0; font-size: 2.5em; }
            header nav { margin-top: 15px; }
            header nav a { color: var(--text-color); text-decoration: none; padding: 10px 15px; margin: 0 5px; border-radius: 5px; transition: background-color 0.3s; }
            header nav a:hover { background-color: var(--accent-color); color: var(--heading-color); }
            section { padding: 40px 0; border-bottom: 1px solid var(--bg-color-light); }
            section h2 { font-size: 2.2em; color: var(--heading-color); text-align: center; margin-bottom: 30px; }
            .overview-banner { width: 100%; height: auto; border-radius: 8px; margin-top: 20px; }
            .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 25px; }
            .card { background: var(--bg-color-dark); border-radius: 8px; overflow: hidden; box-shadow: 0 4px 15px rgba(0,0,0,0.2); }
            .card img { width: 100%; height: 200px; object-fit: cover; display: block; }
            .card-content { padding: 20px; }
            .card h3, .card h4 { margin: 0 0 10px 0; color: var(--heading-color); }
            .news-article { background: var(--bg-color-light); padding: 20px; margin-bottom: 15px; border-radius: 8px; }
            .news-article h4 { margin-top: 0; }
            .news-article div, .news-article p, .news-article li { color: var(--text-color); }
            footer { text-align: center; padding: 20px; margin-top: 30px; font-size: 0.9em; color: rgba(255,255,255,0.7); }
        </style>
    </head>
    <body>
    <header>
        <div class="container">
            <?php if ($logo): ?><a href="#"><img src="<?= $logo ?>" alt="Soap Logo" class="logo"></a><?php endif; ?>
            <h1><?= $site_title ?></h1>
            <nav>
                <a href="#overview">Overview</a>
                <a href="#cast">Cast</a>
                <a href="#episodes">Episodes</a>
                <a href="#news">News</a>
            </nav>
        </div>
    </header>
    <main class="container">
        <section id="overview">
            <h2><?= $tagline ?></h2>
            <p style="text-align: center; max-width: 800px; margin: 0 auto 20px auto;"><?= nl2br($description) ?></p>
            <?php if ($banner): ?><img src="<?= $banner ?>" alt="Banner" class="overview-banner"><?php endif; ?>
        </section>

        <?php if(!empty($cast)): ?><section id="cast">
            <h2>Cast</h2>
            <div class="grid">
            <?php foreach ($cast as $member): ?>
                <div class="card">
                    <?php if(!empty($member['photo'])): ?><img src="<?= htmlspecialchars($member['photo']) ?>" alt="<?= htmlspecialchars($member['name']) ?>"><?php endif; ?>
                    <div class="card-content">
                        <h3><?= htmlspecialchars($member['name']) ?></h3>
                        <p><?= nl2br(htmlspecialchars($member['bio'] ?? '')) ?></p>
                    </div>
                </div>
            <?php endforeach; ?>
            </div>
        </section><?php endif; ?>

        <?php if(!empty($episodes)): ?><section id="episodes">
            <h2>Episodes</h2>
            <div class="grid">
            <?php foreach ($episodes as $ep): ?>
                <div class="card">
                    <?php if(!empty($ep['thumbnail'])): ?><img src="<?= htmlspecialchars($ep['thumbnail']) ?>" alt="<?= htmlspecialchars($ep['title']) ?>"><?php endif; ?>
                    <div class="card-content">
                        <h4><?= htmlspecialchars($ep['title']) ?></h4>
                        <p><?= nl2br(htmlspecialchars($ep['summary'] ?? '')) ?></p>
                    </div>
                </div>
            <?php endforeach; ?>
            </div>
        </section><?php endif; ?>
        
        <?php if(!empty($news)): ?><section id="news">
            <h2>News</h2>
            <?php foreach ($news as $item): ?>
                <article class="news-article">
                    <h4><?= htmlspecialchars($item['headline']) ?></h4>
                    <div><?= $item['body'] ?? '' ?></div>
                </article>
            <?php endforeach; ?>
        </section><?php endif; ?>
    </main>
    <footer><p>© <?= date('Y') ?> <?= $site_title ?></p></footer>
    </body>
    </html>
    <?php
    exit;
}

// ========== ADMIN PANEL LOGIC ==========
@ini_set('session.use_strict_mode', '1');
$secureCookies = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
session_set_cookie_params([
    'lifetime' => 0, 'path' => '/', 'domain' => '',
    'secure' => $secureCookies, 'httponly' => true, 'samesite' => 'Lax',
]);
if (session_status() === PHP_SESSION_NONE) { session_name('SOAPCMS_ADMIN_SESSID'); session_start(); }

header('X-Frame-Options: SAMEORIGIN');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer-when-downgrade');
header("Permissions-Policy: camera=(), microphone=(), geolocation=()");
header("Content-Security-Policy: default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; connect-src 'self'; frame-ancestors 'self';");

define('DS', DIRECTORY_SEPARATOR);
define('BASE_DIR', __DIR__);
define('DATA_DIR', BASE_DIR . DS . 'data');
define('UPLOADS_DIR', BASE_DIR . DS . 'uploads');
define('SOAPS_FILE', DATA_DIR . DS . 'soaps.json');
define('USERS_FILE', DATA_DIR . DS . 'users.json');
define('CURRENT_URL', basename(__FILE__));
$MAX_UPLOAD_BYTES = 2 * 1024 * 1024;
$ALLOWED_MIME = ['image/png' => 'png', 'image/jpeg' => 'jpg', 'image/webp' => 'webp', 'image/gif' => 'gif'];
$GOOGLE_FONTS = ['Open Sans', 'Roboto', 'Lato', 'Montserrat', 'Merriweather', 'Playfair Display'];

$authed = !empty($_SESSION['admin_logged_in']);
$soap_id = isset($_GET['soap_id']) ? preg_replace('/[^a-z0-9_-]/i', '', $_GET['soap_id']) : null;
$page = $_GET['p'] ?? 'dashboard';
$context = $soap_id ? 'soap' : 'global';

function h(?string $str): string { return htmlspecialchars((string)$str, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function redirect(string $url): void { header("Location: $url"); exit; }
function now_iso(): string { return (new DateTimeImmutable('now'))->format('c'); }
function slugify(string $name): string {
    $s = strtolower(trim($name));
    $s = preg_replace('/[^a-z0-9]+/i', '-', $s);
    return trim($s, '-') ?: bin2hex(random_bytes(4));
}
function generate_csrf(): string {
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
    return $_SESSION['csrf'];
}
function verify_csrf(?string $token): bool { return hash_equals($_SESSION['csrf'] ?? '', (string)$token); }

function read_json(string $path, array $default = []): array {
    if (!file_exists($path)) return $default;
    $fp = @fopen($path, 'r');
    if (!$fp) return $default;
    flock($fp, LOCK_SH);
    $json = stream_get_contents($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    $data = json_decode($json ?: '', true);
    return is_array($data) ? $data : $default;
}

function write_json(string $path, array $data): bool {
    $dir = dirname($path);
    if (!is_dir($dir)) @mkdir($dir, 0775, true);
    $tmp = $path . '.tmp';
    $fp = @fopen($tmp, 'w');
    if (!$fp) return false;
    flock($fp, LOCK_EX);
    $ok = fwrite($fp, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) !== false;
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    return $ok ? @rename($tmp, $path) : false;
}

function validated_upload(array $file, string $destDir, array $allowedMime, int $maxBytes, string $prefix = ''): array {
    if ($file['error'] !== UPLOAD_ERR_OK) return [false, 'Upload error: code ' . $file['error']];
    if ($file['size'] > $maxBytes) return [false, 'File too large.'];
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime = $finfo->file($file['tmp_name']);
    if (!isset($allowedMime[$mime])) return [false, 'Unsupported image type.'];
    if (!is_dir($destDir)) @mkdir($destDir, 0775, true);
    $ext = $allowedMime[$mime];
    $safeName = ($prefix ? $prefix . '-' : '') . bin2hex(random_bytes(8)) . '.' . $ext;
    $destPath = rtrim($destDir, DS) . DS . $safeName;
    if (!move_uploaded_file($file['tmp_name'], $destPath)) return [false, 'Failed to save upload.'];
    @chmod($destPath, 0644);
    $relative_path = str_replace(BASE_DIR . DS, '', $destPath);
    return [true, str_replace(DS, '/', $relative_path)];
}

function rrmdir(string $dir): void {
    if (!is_dir($dir)) return;
    $objects = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($objects as $object) {
        if ($object->isDir()) rmdir($object->getRealPath()); else unlink($object->getRealPath());
    }
    rmdir($dir);
}

$errors = []; $notices = [];
if (isset($_GET['logout'])) {
    session_regenerate_id(true); $_SESSION = []; session_destroy();
    redirect(CURRENT_URL);
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'login') {
    if (!verify_csrf($_POST['csrf'] ?? '')) { $errors[] = 'Invalid security token.'; }
    else {
        $users = read_json(USERS_FILE);
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';
        if (isset($users[$username]) && $password === ($users[$username]['password'] ?? null)) {
            session_regenerate_id(true); $_SESSION['admin_logged_in'] = true; $_SESSION['admin_name'] = $username;
            redirect(CURRENT_URL);
        } else {
            usleep(random_int(200000, 500000)); $errors[] = 'Invalid username or password.';
        }
    }
}
$csrf = generate_csrf();
$adminName = $_SESSION['admin_name'] ?? 'Admin';

@mkdir(DATA_DIR, 0775, true);
@mkdir(UPLOADS_DIR, 0775, true);
$all_soaps_data = read_json(SOAPS_FILE, ['soaps' => []]);
$all_soaps = $all_soaps_data['soaps'];
$current_soap = null;
if ($soap_id) {
    foreach ($all_soaps as $s) { if ($s['id'] === $soap_id) { $current_soap = $s; break; }}
    if (!$current_soap) { redirect(CURRENT_URL); }
}

if ($authed && $_SERVER['REQUEST_METHOD'] === 'POST' && verify_csrf($_POST['csrf'] ?? null)) {
    $action = $_POST['action'] ?? '';
    if ($context === 'global') {
        if ($action === 'create_soap' || $action === 'update_soap') {
            $name = trim($_POST['name'] ?? ''); $slug = trim($_POST['slug'] ?? '') ?: slugify($name);
            $id = $action === 'create_soap' ? $slug : ($_POST['id'] ?? '');
            if (!$name || !$id) { $errors[] = 'Soap Name is required.'; }
            else {
                $is_new = ($action === 'create_soap'); $found = false; $idx = -1;
                foreach ($all_soaps as $i => $s) { if ($s['id'] === $id) { $found = true; $idx = $i; break; } }
                if ($is_new && $found) { $errors[] = "Soap with ID '$id' already exists."; }
                elseif (!$is_new && !$found) { $errors[] = "Soap to update not found."; }
                else {
                    $soap_data = $is_new ? [] : $all_soaps[$idx];
                    $soap_data = array_merge($soap_data, ['id' => $id, 'name' => $name, 'slug' => $slug]);
                    if (isset($_FILES['logo']) && $_FILES['logo']['error'] !== UPLOAD_ERR_NO_FILE) {
                        [$ok, $res] = validated_upload($_FILES['logo'], UPLOADS_DIR . DS . 'logos', $ALLOWED_MIME, $MAX_UPLOAD_BYTES);
                        if ($ok) { $soap_data['logo'] = $res; } else { $errors[] = $res; }
                    }
                    if (!$errors) {
                        if ($is_new) { $all_soaps[] = $soap_data; } else { $all_soaps[$idx] = $soap_data; }
                        if (write_json(SOAPS_FILE, ['soaps' => $all_soaps])) {
                            @mkdir(DATA_DIR . DS . $id, 0775, true);
                            $notices[] = "Soap " . ($is_new ? 'created' : 'updated') . ".";
                        } else { $errors[] = "Failed to save soap data."; }
                    }
                }
            }
        } elseif ($action === 'delete_soap') {
            $id = $_POST['id'] ?? '';
            $all_soaps = array_values(array_filter($all_soaps, fn($s) => $s['id'] !== $id));
            if (write_json(SOAPS_FILE, ['soaps' => $all_soaps])) {
                rrmdir(DATA_DIR . DS . $id); rrmdir(UPLOADS_DIR . DS . $id);
                $notices[] = "Soap '$id' and all its data deleted.";
            } else { $errors[] = "Failed to delete soap."; }
        }
    }
    elseif ($context === 'soap' && $current_soap) {
        $soap_data_dir = DATA_DIR . DS . $current_soap['id'];
        $soap_uploads_dir = UPLOADS_DIR . DS . $current_soap['id'];

        $module_configs = [
            'cast' => ['file' => 'cast.json', 'key' => 'cast', 'id' => 'item_id'],
            'episodes' => ['file' => 'episodes.json', 'key' => 'episodes', 'id' => 'item_id'],
            'news' => ['file' => 'news.json', 'key' => 'news', 'id' => 'item_id'],
        ];

        if (array_key_exists($page, $module_configs)) {
            $cfg = $module_configs[$page];
            $file = $soap_data_dir . DS . $cfg['file'];
            $data = read_json($file, [$cfg['key'] => []]);
            $items = $data[$cfg['key']];

            if ($action === 'save_' . $page) {
                $item_id = $_POST[$cfg['id']] ?: $page . '-' . bin2hex(random_bytes(6));
                $idx = -1; foreach($items as $i => $item) { if($item['id'] === $item_id) { $idx = $i; break; }};
                $item_data = ($idx > -1) ? $items[$idx] : ['id' => $item_id];

                $fields_map = [
                    'cast' => ['name' => 'text', 'bio' => 'textarea', 'photo' => 'file'],
                    'episodes' => ['title' => 'text', 'summary' => 'textarea', 'thumbnail' => 'file'],
                    'news' => ['headline' => 'text', 'body' => 'textarea-html'],
                ];
                
                foreach ($fields_map[$page] as $field => $type) {
                    if ($type === 'file' && isset($_FILES[$field]) && $_FILES[$field]['error'] === UPLOAD_ERR_OK) {
                        [$ok, $res] = validated_upload($_FILES[$field], $soap_uploads_dir . DS . $page, $ALLOWED_MIME, $MAX_UPLOAD_BYTES);
                        if ($ok) $item_data[$field] = $res; else $errors[] = $res;
                    } elseif ($type !== 'file' && isset($_POST[$field])) {
                        $item_data[$field] = $_POST[$field];
                    }
                }
                
                if (!$errors) {
                    if ($idx > -1) { $items[$idx] = $item_data; } else { $items[] = $item_data; }
                    if(write_json($file, [$cfg['key'] => $items])) { $notices[] = ucfirst($page) . " item saved."; } else { $errors[] = "Failed to save."; }
                }
            } elseif ($action === 'delete_' . $page) {
                $item_id = $_POST[$cfg['id']] ?? '';
                $items = array_values(array_filter($items, fn($item) => $item['id'] !== $item_id));
                if (write_json($file, [$cfg['key'] => $items])) { $notices[] = ucfirst($page) . " item deleted."; } else { $errors[] = "Failed to delete."; }
            }
        }
        if ($page === 'settings' && $action === 'save_settings') {
            $settings_file = $soap_data_dir . DS . 'settings.json';
            $settings = read_json($settings_file);
            $settings['site_title'] = $_POST['site_title'] ?? '';
            $settings['tagline'] = $_POST['tagline'] ?? '';
            $settings['description'] = $_POST['description'] ?? '';
            $settings['theme']['primary_color'] = $_POST['primary_color'] ?? '#2eaadc';
            $settings['theme']['accent_color'] = $_POST['accent_color'] ?? '#e6f2ff';
            $settings['theme']['font'] = $_POST['font'] ?? 'Open Sans';
            if (isset($_FILES['banner_image']) && $_FILES['banner_image']['error'] === UPLOAD_ERR_OK) {
                [$ok, $res] = validated_upload($_FILES['banner_image'], $soap_uploads_dir . DS . 'settings', $ALLOWED_MIME, $MAX_UPLOAD_BYTES);
                if ($ok) $settings['banner_image'] = $res; else $errors[] = $res;
            }
            if (!$errors && write_json($settings_file, $settings)) { $notices[] = 'Settings saved.'; } else { $errors[] = 'Failed to save settings.'; }
        }
    }
}

ob_start();

function render_login_page(string $csrf, array $errors): void { ?>
    <div class="admin-bar">
        <div class="brand"><img src="logo2.png" alt="Logo"> <span>Soap CMS</span></div>
    </div>
    <div style="max-width:460px;margin:10vh auto;padding:24px;background:var(--panel);border:1px solid var(--border);border-radius:12px;box-shadow:var(--shadow);">
        <h2 style="margin:0 0 10px 0;">Welcome back</h2>
        <?php foreach ($errors as $e): ?><div class="notice error"><?= h($e) ?></div><?php endforeach; ?>
        <form method="post" autocomplete="on" novalidate>
            <input type="hidden" name="action" value="login" /><input type="hidden" name="csrf" value="<?= h($csrf) ?>" />
            <div class="field"><label for="username">Username</label><input id="username" name="username" type="text" required autofocus /></div>
            <div class="field"><label for="password">Password</label><input id="password" name="password" type="password" required /></div>
            <div style="margin-top:12px;"><button class="btn primary" type="submit"><i class="fa-solid fa-right-to-bracket"></i> Sign in</button></div>
        </form>
    </div>
<?php }

function render_global_dashboard(array $soaps, string $csrf): void { ?>
    <div class="toolbar"><h1>Soaps Dashboard</h1><button class="btn primary" onclick="openSoapModal()"><i class="fa-solid fa-plus"></i> Add New Soap</button></div>
    <div style="overflow-x:auto; border-radius:var(--radius);"><table class="list">
        <thead><tr><th>Logo</th><th>Name</th><th>Public Link</th><th style="width: 220px;">Actions</th></tr></thead>
        <tbody>
        <?php if (empty($soaps)): ?>
            <tr><td colspan="4" class="muted" style="padding:20px; text-align:center;">No soaps created yet.</td></tr>
        <?php else: foreach ($soaps as $s): ?>
            <tr>
                <td><?php if (!empty($s['logo'])): ?><img class="logo" src="<?= h($s['logo']) ?>" alt="logo"><?php else: ?><div class="logo logo-placeholder"><span><?= strtoupper(substr($s['name'] ?? '?',0,1)) ?></span></div><?php endif; ?></td>
                <td><strong><?= h($s['name'] ?? '') ?></strong><br><span class="muted"><?= h($s['slug'] ?? '') ?></span></td>
                <td><a href="?view=public&soap_id=<?=h($s['id'])?>" target="_blank">View Site <i class="fa-solid fa-arrow-up-right-from-square"></i></a></td>
                <td>
                    <a href="?soap_id=<?=h($s['id'])?>" class="btn"><i class="fa-solid fa-cogs"></i> Manage</a>
                    <button class="btn" onclick='openSoapModal(<?= json_encode($s) ?>)'><i class="fa-solid fa-pen"></i></button>
                    <form method="post" style="display:inline" onsubmit="return confirm('DELETE this soap and ALL its data? This cannot be undone.');">
                        <input type="hidden" name="csrf" value="<?= h($csrf) ?>" /><input type="hidden" name="action" value="delete_soap" />
                        <input type="hidden" name="id" value="<?= h($s['id']) ?>" /><button class="btn danger" type="submit"><i class="fa-solid fa-trash"></i></button>
                    </form>
                </td>
            </tr>
        <?php endforeach; endif; ?>
        </tbody>
    </table></div>
<?php }

function render_soap_dashboard(array $soap): void {
    echo "<h1>Dashboard: " . h($soap['name']) . "</h1><p class='muted'>You are managing the \"" . h($soap['name']) . "\" soap. Use the sidebar to manage its content.</p>";
    echo '<div class="cards">';
    $counts = ['cast' => 0, 'episodes' => 0, 'news' => 0];
    foreach ($counts as $key => &$count) {
        $data = read_json(DATA_DIR . DS . $soap['id'] . DS . $key . '.json', [$key => []]);
        $count = count($data[$key]);
    }
    foreach ($counts as $key => $count) {
        echo "<div class='card'><div class='muted'>" . ucfirst($key) . "</div><div class='kpi'>$count</div></div>";
    }
    echo '</div>';
}

function render_crud_page(string $title, string $page_key, array $soap, string $csrf, array $fields, array $columns): void {
    $data = read_json(DATA_DIR . DS . $soap['id'] . DS . $page_key . '.json', [$page_key => []]);
    $items = $data[$page_key];
    ?>
    <div class="toolbar"><h1><?= h($title) ?></h1><button class="btn primary" onclick="openModal('<?= $page_key ?>Modal')"><i class="fa-solid fa-plus"></i> Add New</button></div>
    <div style="overflow-x:auto; border-radius:var(--radius);"><table class="list">
        <thead><tr>
            <?php foreach($columns as $col_key => $col_name): ?><th <?= $col_key === 'actions' ? 'style="width:150px;"' : '' ?>><?= $col_name ?></th><?php endforeach; ?>
        </tr></thead>
        <tbody>
        <?php if (empty($items)): ?>
            <tr><td colspan="<?= count($columns) ?>" class="muted" style="padding:20px; text-align:center;">No items added yet.</td></tr>
        <?php else: foreach (array_reverse($items) as $item): ?>
            <tr>
            <?php foreach($columns as $col_key => $col_name): ?>
                <td>
                <?php if ($col_key === 'actions'): ?>
                    <button class="btn" onclick='openModal("<?= $page_key ?>Modal", <?= json_encode($item) ?>)'><i class="fa-solid fa-pen"></i> Edit</button>
                    <form method="post" style="display:inline" onsubmit="return confirm('Delete this item?');">
                        <input type="hidden" name="csrf" value="<?= h($csrf) ?>" /><input type="hidden" name="action" value="delete_<?= $page_key ?>" />
                        <input type="hidden" name="item_id" value="<?= h($item['id']) ?>" /><button class="btn danger" type="submit"><i class="fa-solid fa-trash"></i></button>
                    </form>
                <?php elseif (in_array($col_key, ['photo', 'thumbnail'])): ?>
                    <?php if (!empty($item[$col_key])): ?><img class="logo" src="<?= h($item[$col_key]) ?>" alt="image"><?php else: ?><div class="logo logo-placeholder"><i class="fa fa-image"></i></div><?php endif; ?>
                <?php else: ?>
                    <strong><?= h($item[$col_key] ?? '') ?></strong>
                <?php endif; ?>
                </td>
            <?php endforeach; ?>
            </tr>
        <?php endforeach; endif; ?>
        </tbody>
    </table></div>
<?php }

function render_settings_page(array $soap, string $csrf, array $google_fonts): void {
    $settings = read_json(DATA_DIR . DS . $soap['id'] . DS . 'settings.json');
    ?>
    <div class="toolbar"><h1>Site Settings</h1></div>
    <div class="card" style="max-width: 800px;">
        <form method="post" enctype="multipart/form-data">
            <input type="hidden" name="action" value="save_settings" /><input type="hidden" name="csrf" value="<?= h($csrf) ?>" />
            <div class="field"><label for="site_title">Site Title</label><input type="text" id="site_title" name="site_title" value="<?= h($settings['site_title'] ?? '') ?>"></div>
            <div class="field"><label for="tagline">Tagline</label><input type="text" id="tagline" name="tagline" value="<?= h($settings['tagline'] ?? '') ?>"></div>
            <div class="field"><label for="description">Description</label><textarea id="description" name="description" rows="4"><?= h($settings['description'] ?? '') ?></textarea></div>
            <div class="field"><label for="banner_image">Banner Image</label><input type="file" id="banner_image" name="banner_image" accept="<?= implode(',', array_keys($GLOBALS['ALLOWED_MIME'])) ?>" />
            <?php if(!empty($settings['banner_image'])): ?><img src="<?=h($settings['banner_image'])?>" style="max-width:200px;margin-top:10px;border-radius:var(--radius);"><?php endif; ?></div>
            <hr style="border-color: var(--border); margin: 20px 0;">
            <h3>Theme</h3>
            <div class="field"><label for="primary_color">Primary Color</label><input type="color" id="primary_color" name="primary_color" value="<?= h($settings['theme']['primary_color'] ?? '#2eaadc') ?>"></div>
            <div class="field"><label for="accent_color">Accent Color</label><input type="color" id="accent_color" name="accent_color" value="<?= h($settings['theme']['accent_color'] ?? '#e6f2ff') ?>"></div>
            <div class="field"><label for="font">Font Family</label><select id="font" name="font">
                <?php foreach($google_fonts as $font): ?>
                <option value="<?= h($font) ?>" <?= ($settings['theme']['font'] ?? '') === $font ? 'selected' : '' ?>><?= h($font) ?></option>
                <?php endforeach; ?>
            </select></div>
            <div style="margin-top:16px;"><button class="btn primary" type="submit"><i class="fa-solid fa-floppy-disk"></i> Save Settings</button></div>
        </form>
    </div>
<?php }

function render_crud_modal(string $title, string $page_key, string $csrf, array $fields): void { ?>
    <div class="modal-backdrop" id="<?= $page_key ?>Modal" role="dialog" aria-modal="true">
        <div class="modal">
            <div class="modal-head"><strong id="<?= $page_key ?>ModalTitle">Add New <?= h($title) ?></strong><button class="btn" onclick="closeModal('<?= $page_key ?>Modal')"><i class="fa-solid fa-xmark"></i></button></div>
            <form id="<?= $page_key ?>Form" class="modal-body" method="post" enctype="multipart/form-data">
                <input type="hidden" name="csrf" value="<?= h($csrf) ?>" /><input type="hidden" name="action" value="save_<?= $page_key ?>" />
                <input type="hidden" name="item_id" id="<?= $page_key ?>_id" />
                <?php foreach($fields as $key => $field): ?>
                    <div class="field">
                        <label for="<?= $page_key ?>_<?= $key ?>"><?= h($field['label']) ?></label>
                        <?php if ($field['type'] === 'textarea'): ?>
                            <textarea id="<?= $page_key ?>_<?= $key ?>" name="<?= $key ?>" rows="5"></textarea>
                        <?php elseif ($field['type'] === 'textarea-html'): ?>
                             <textarea class="tinymce-basic" id="<?= $page_key ?>_<?= $key ?>" name="<?= $key ?>" rows="8"></textarea>
                        <?php elseif ($field['type'] === 'file'): ?>
                            <input type="file" id="<?= $page_key ?>_<?= $key ?>" name="<?= $key ?>" accept="<?= implode(',', array_keys($GLOBALS['ALLOWED_MIME'])) ?>" />
                        <?php else: ?>
                            <input type="text" id="<?= $page_key ?>_<?= $key ?>" name="<?= $key ?>" required />
                        <?php endif; ?>
                    </div>
                <?php endforeach; ?>
                <div style="margin-top:16px; display:flex; gap:10px;"><button class="btn primary" type="submit"><i class="fa-solid fa-floppy-disk"></i> Save</button></div>
            </form>
        </div>
    </div>
<?php }
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" /><meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <title><?= $current_soap ? h($current_soap['name']) . ' · ' : '' ?>Admin · Soap CMS</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <link rel="preconnect" href="https://fonts.googleapis.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Open+Sans:wght@400;600;700&display=swap" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css" rel="stylesheet">
    <style>
    :root { --bg: #0f1720; --panel: #141e29; --panel-2: #0f1a24; --text: #e6f2ff; --muted: #9ab6d1; --accent: #2eaadc; --border: #1e2e3d; --shadow: 0 6px 24px rgba(0,0,0,.3); --radius: 10px; --danger: #ff5a5f; }
    * { box-sizing: border-box; }
    html, body { margin: 0; padding: 0; background: var(--bg); color: var(--text); font-family: "Open Sans", system-ui, sans-serif; }
    a { color: var(--accent); text-decoration: none; } a:hover { text-decoration: underline; }
    h1, h2 { margin-top: 0; }
    .admin-bar { position: sticky; top: 0; z-index: 1000; display: flex; align-items: center; justify-content: space-between; padding: 10px 16px; background: #0c141d; border-bottom: 1px solid var(--border); }
    .brand { display: flex; align-items: center; gap: 10px; font-weight: 700; } .brand img { height: 24px; }
    .bar-actions { display: flex; align-items: center; gap: 16px; }
    .bar-actions .pill { background: var(--panel); padding: 6px 10px; border: 1px solid var(--border); border-radius: 999px; color: var(--muted); display: inline-flex; align-items: center; gap: 8px; }
    .wrap { display: grid; grid-template-columns: 260px 1fr; min-height: calc(100vh - 48px); }
    .sidebar { border-right: 1px solid var(--border); background: var(--panel-2); padding: 14px 10px; position: sticky; top: 48px; height: calc(100vh - 48px); overflow-y: auto; }
    .menu { list-style: none; margin: 0; padding: 0; } .menu li { margin: 4px 8px; }
    .menu a { display: flex; align-items: center; gap: 10px; padding: 10px 12px; border-radius: 8px; color: var(--text); }
    .menu a.active, .menu a:hover { background: var(--panel); }
    .sub-menu-title { padding: 10px 12px; font-size: 11px; text-transform: uppercase; color: var(--muted); letter-spacing: 0.5px; border-top: 1px solid var(--border); margin-top: 10px; }
    .content { padding: 20px; }
    .notice { padding: 12px 14px; border-radius: 8px; margin-bottom: 16px; border: 1px solid var(--border); background: #12212f; }
    .notice.success { border-color: #114032; background: #0d2a21; color: #b8f2d4; }
    .notice.error { border-color: #4a1d23; background: #2a1013; color: #ffd5da; }
    .cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 14px; margin-bottom: 16px; }
    .card { background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius); padding: 14px; box-shadow: var(--shadow); }
    .card .kpi { font-size: 24px; font-weight: 700; margin-top: 6px; }
    .toolbar { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 16px; }
    .btn { display: inline-flex; align-items: center; gap: 8px; border: 1px solid var(--border); border-radius: 8px; padding: 8px 12px; color: var(--text); background: linear-gradient(180deg, #182736, #101a24); cursor: pointer; white-space: nowrap; }
    .btn.primary { border-color: #0c3d5b; background: linear-gradient(180deg, #1d4c6a, #13354a); }
    .btn.danger { border-color: #62232a; background: linear-gradient(180deg, #6a1d27, #3a1218); color: #ffd5da; } .btn:hover { filter: brightness(1.05); }
    .list { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }
    .list th, .list td { padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: middle; text-align: left; }
    .list th { background: #0f1c28; font-weight: 600; font-size: 13px; color: var(--muted); } .list tr:hover td { background: #0e1a25; }
    .logo { width: 42px; height: 42px; border-radius: 6px; object-fit: cover; border: 1px solid var(--border); background: #0a131c; }
    .logo-placeholder { display:flex; align-items:center; justify-content:center; color: var(--muted); font-size: 1.2em; }
    .modal-backdrop { position: fixed; inset: 0; background: rgba(0,0,0,.6); display: none; align-items: center; justify-content: center; z-index: 2000; }
    .modal { width: min(600px, 95vw); background: var(--panel); border: 1px solid var(--border); border-radius: 12px; box-shadow: var(--shadow); overflow: hidden; display: flex; flex-direction: column; max-height: 90vh; }
    .modal-head { display:flex; align-items:center; justify-content: space-between; padding: 12px 14px; background: #0f1c28; border-bottom: 1px solid var(--border); flex-shrink: 0;}
    .modal-body { padding: 14px; overflow-y: auto; }
    .field { margin-bottom: 10px; } .field label { display:block; margin-bottom: 6px; color: var(--muted); font-size: 13px; }
    .field input[type="text"], .field input[type="password"], .field input[type="file"], .field select, .field textarea, .field input[type="color"] { width:100%; padding:10px; background:#0e1b26; color: var(--text); border:1px solid var(--border); border-radius:8px; }
    .field input[type="color"] { padding: 2px; height: 42px; }
    .muted { color: var(--muted); font-size: 13px; }
    .footer { color: var(--muted); font-size: 12px; padding: 16px; text-align: center; border-top: 1px solid var(--border); margin-top: 20px; }
    #menu-toggle { display: none; }
    .sidebar-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,.5); z-index: 998; }
    .pill span.mobile-hide { display: inline; }
    @media (max-width: 992px) {
        .wrap { grid-template-columns: 1fr; }
        .sidebar { position: fixed; top: 0; left: 0; bottom: 0; width: 260px; transform: translateX(-100%); transition: transform 0.3s ease-in-out; z-index: 1100; height: 100vh; padding-top: 60px; }
        .wrap.sidebar-open .sidebar { transform: translateX(0); box-shadow: var(--shadow); }
        .wrap.sidebar-open .sidebar-overlay { display: block; }
        #menu-toggle { display: inline-flex; }
        .content { padding: 12px; }
        .toolbar { flex-wrap: wrap; }
        .list td:last-child { display: flex; gap: 5px; align-items: stretch; flex-wrap: wrap; }
        .list td:last-child .btn, .list td:last-child form { flex-grow: 1; } .list td:last-child .btn { justify-content: center; }
    }
    @media (max-width: 768px) { .pill span.mobile-hide { display: none; } }
    </style>
</head>
<body>

<?php if (!$authed): render_login_page($csrf, $errors); else: ?>
    <div class="admin-bar">
        <div class="brand">
            <button class="btn" id="menu-toggle" aria-label="Toggle menu"><i class="fa-solid fa-bars"></i></button>
            <img src="logo2.png" alt="Logo"> <span>Soap CMS</span>
        </div>
        <div class="bar-actions">
            <span class="pill"><i class="fa-solid fa-user-shield"></i> <span class="mobile-hide"><?= h($adminName) ?></span></span>
            <a class="pill" href="?logout=1" onclick="return confirm('Log out now?');"><i class="fa-solid fa-arrow-right-from-bracket"></i> <span class="mobile-hide">Logout</span></a>
        </div>
    </div>
    <div class="wrap">
        <div class="sidebar-overlay"></div>
        <aside class="sidebar">
            <ul class="menu">
            <?php if ($context === 'global'): ?>
                <li><a href="<?= h(CURRENT_URL) ?>" class="active"><i class="fa-solid fa-list fa-fw"></i> All Soaps</a></li>
            <?php else: ?>
                <li><a href="<?= h(CURRENT_URL) ?>"><i class="fa-solid fa-arrow-left fa-fw"></i> All Soaps</a></li>
                <li class="sub-menu-title"><?= h($current_soap['name']) ?> Menu</li>
                <li><a href="?soap_id=<?=h($soap_id)?>&p=dashboard" class="<?= $page === 'dashboard' ? 'active' : '' ?>"><i class="fa-solid fa-gauge fa-fw"></i> Dashboard</a></li>
                <li><a href="?soap_id=<?=h($soap_id)?>&p=cast" class="<?= $page === 'cast' ? 'active' : '' ?>"><i class="fa-solid fa-users fa-fw"></i> Cast</a></li>
                <li><a href="?soap_id=<?=h($soap_id)?>&p=episodes" class="<?= $page === 'episodes' ? 'active' : '' ?>"><i class="fa-solid fa-clapperboard fa-fw"></i> Episodes</a></li>
                <li><a href="?soap_id=<?=h($soap_id)?>&p=news" class="<?= $page === 'news' ? 'active' : '' ?>"><i class="fa-solid fa-newspaper fa-fw"></i> News</a></li>
                <li><a href="?soap_id=<?=h($soap_id)?>&p=settings" class="<?= $page === 'settings' ? 'active' : '' ?>"><i class="fa-solid fa-palette fa-fw"></i> Settings</a></li>
            <?php endif; ?>
            </ul>
        </aside>

        <main class="content">
            <?php foreach ($notices as $n): ?><div class="notice success"><?= h($n) ?></div><?php endforeach; ?>
            <?php foreach ($errors as $e): ?><div class="notice error"><?= h($e) ?></div><?php endforeach; ?>
            <?php
            if ($context === 'global') { render_global_dashboard($all_soaps, $csrf); }
            elseif ($context === 'soap' && $current_soap) {
                switch ($page) {
                    case 'cast': render_crud_page('Cast', 'cast', $current_soap, $csrf, ['name' => ['label' => 'Character Name', 'type' => 'text'], 'photo' => ['label' => 'Photo', 'type' => 'file'], 'bio' => ['label' => 'Biography', 'type' => 'textarea']], ['photo' => 'Photo', 'name' => 'Name', 'actions' => 'Actions']); break;
                    case 'episodes': render_crud_page('Episodes', 'episodes', $current_soap, $csrf, ['title' => ['label' => 'Episode Title', 'type' => 'text'], 'thumbnail' => ['label' => 'Thumbnail', 'type' => 'file'], 'summary' => ['label' => 'Summary', 'type' => 'textarea']], ['thumbnail' => 'Thumbnail', 'title' => 'Title', 'actions' => 'Actions']); break;
                    case 'news': render_crud_page('News', 'news', $current_soap, $csrf, ['headline' => ['label' => 'Headline', 'type' => 'text'], 'body' => ['label' => 'Body', 'type' => 'textarea-html']], ['headline' => 'Headline', 'actions' => 'Actions']); break;
                    case 'settings': render_settings_page($current_soap, $csrf, $GOOGLE_FONTS); break;
                    default: render_soap_dashboard($current_soap); break;
                }
            }
            ?>
        </main>
    </div>
    <div class="footer">© <?= date('Y') ?> Soap CMS</div>

    <div class="modal-backdrop" id="soapModal" role="dialog" aria-modal="true">
        <div class="modal"><div class="modal-head"><strong id="soapModalTitle">Add New Soap</strong><button class="btn" onclick="closeModal('soapModal')"><i class="fa-solid fa-xmark"></i></button></div>
            <form id="soapForm" class="modal-body" method="post" enctype="multipart/form-data">
                <input type="hidden" name="csrf" value="<?= h($csrf) ?>" /><input type="hidden" name="action" id="soapAction" value="create_soap" /><input type="hidden" name="id" id="s_id" />
                <div class="field"><label for="s_name">Soap Name</label><input type="text" id="s_name" name="name" required /></div>
                <div class="field"><label for="s_slug">Soap Slug/ID (auto-generated, cannot be changed after creation)</label><input type="text" id="s_slug" name="slug" required /></div>
                <div class="field"><label for="s_logo">Logo</label><input type="file" id="s_logo" name="logo" accept="<?= implode(',', array_keys($ALLOWED_MIME)) ?>" /></div>
                <div style="margin-top:16px; display:flex; gap:10px;"><button class="btn primary" type="submit"><i class="fa-solid fa-floppy-disk"></i> Save</button></div>
            </form>
        </div>
    </div>
    <?php if ($context === 'soap'):
        render_crud_modal('Cast Member', 'cast', $csrf, ['name' => ['label' => 'Character Name', 'type' => 'text'], 'photo' => ['label' => 'Photo', 'type' => 'file'], 'bio' => ['label' => 'Biography', 'type' => 'textarea']]);
        render_crud_modal('Episode', 'episodes', $csrf, ['title' => ['label' => 'Episode Title', 'type' => 'text'], 'thumbnail' => ['label' => 'Thumbnail', 'type' => 'file'], 'summary' => ['label' => 'Summary', 'type' => 'textarea']]);
        render_crud_modal('News Article', 'news', $csrf, ['headline' => ['label' => 'Headline', 'type' => 'text'], 'body' => ['label' => 'Body', 'type' => 'textarea-html']]);
    endif; ?>
<?php endif; ?>

<script src="https://cdn.jsdelivr.net/npm/tinymce@6.8.3/tinymce.min.js" referrerpolicy="origin"></script>
<script>
document.addEventListener('DOMContentLoaded', function() {
    tinymce.init({ selector: '.tinymce-basic', menubar: false, plugins: 'link lists code', toolbar: 'bold italic underline | bullist numlist | link | code', skin: 'oxide-dark', content_css: 'dark', height: 220 });
    const menuToggle = document.getElementById('menu-toggle'), wrap = document.querySelector('.wrap'), overlay = document.querySelector('.sidebar-overlay');
    if (menuToggle) {
      menuToggle.addEventListener('click', (e) => { e.stopPropagation(); wrap.classList.toggle('sidebar-open'); });
      overlay.addEventListener('click', () => { wrap.classList.remove('sidebar-open'); });
    }
});

function slugify(text) { return text.toString().toLowerCase().trim().replace(/\s+/g, '-').replace(/[^\w\-]+/g, '').replace(/\-\-+/g, '-'); }
function closeModal(modalId) { document.getElementById(modalId)?.style.display = 'none'; }
function openModal(modalId, data = null) {
    const modal = document.getElementById(modalId);
    if (!modal) return;
    const form = modal.querySelector('form');
    form.reset();
    const prefix = modalId.replace('Modal','');
    form.querySelector(`#${prefix}ModalTitle`).textContent = `Add New ${prefix.charAt(0).toUpperCase() + prefix.slice(1)}`;
    form.querySelector('input[name="item_id"]').value = '';
    
    if (data) {
        form.querySelector(`#${prefix}ModalTitle`).textContent = `Edit ${prefix.charAt(0).toUpperCase() + prefix.slice(1)}`;
        for (const key in data) {
            const el = form.querySelector(`[name="${key}"]`);
            if (el) {
                if (el.tagName === 'TEXTAREA' && el.classList.contains('tinymce-basic') && tinymce.get(el.id)) {
                    tinymce.get(el.id).setContent(data[key]);
                } else {
                    el.value = data[key];
                }
            }
        }
    }
    modal.style.display = 'flex';
}
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') { document.querySelectorAll('.modal-backdrop').forEach(m => m.style.display = 'none'); }});
const s_name = document.getElementById('s_name'), s_slug = document.getElementById('s_slug');
if (s_name) s_name.addEventListener('input', () => { if (!document.getElementById('s_id').value) { s_slug.value = slugify(s_name.value); }});
function openSoapModal(soapData = null) {
    const form = document.getElementById('soapForm'); form.reset();
    if (soapData) {
        document.getElementById('soapModalTitle').textContent = 'Edit Soap';
        document.getElementById('soapAction').value = 'update_soap';
        document.getElementById('s_id').value = soapData.id;
        document.getElementById('s_name').value = soapData.name;
        document.getElementById('s_slug').value = soapData.slug;
        document.getElementById('s_slug').readOnly = true;
    } else {
        document.getElementById('soapModalTitle').textContent = 'Add New Soap';
        document.getElementById('soapAction').value = 'create_soap';
        document.getElementById('s_id').value = '';
        document.getElementById('s_slug').readOnly = false;
    }
    document.getElementById('soapModal').style.display = 'flex';
}
</script>
</body>
</html>
