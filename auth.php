$usersPath = __DIR__ . '/data/users.json';
$users = json_decode(file_get_contents($usersPath), true);

$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';

if (isset($users[$username]) && $password === $users[$username]['password']) {
    session_start();
    $_SESSION['user'] = $username;
    header('Location: admin.php');
    exit;
} else {
    echo "Invalid login.";
}