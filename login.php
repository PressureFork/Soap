<?php
session_start();
if (isset($_SESSION['user'])) {
    header('Location: admin.php');
    exit;
}
?>

<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
    <form action="auth.php" method="post">
        <label>Username: <input type="text" name="username" required></label><br>
        <label>Password: <input type="password" name="password" required></label><br>
        <button type="submit">Login</button>
    </form>
</body>
</html>