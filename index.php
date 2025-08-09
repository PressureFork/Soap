<?php
// Load soap registry and filter for published soaps
$soaps = [];
$admin_script_name = 'admin.php'; // IMPORTANT: Change this if your admin panel file has a different name.

if (file_exists(__DIR__ . '/data/soaps.json')) {
  $json = file_get_contents(__DIR__ . '/data/soaps.json');
  $data = json_decode($json, true);
  // Ensure we only process soaps that are marked as 'published' in the admin panel
  if (isset($data['soaps']) && is_array($data['soaps'])) {
    foreach ($data['soaps'] as $soap) {
      if (isset($soap['status']) && $soap['status'] === 'published') {
        $soaps[] = $soap;
      }
    }
  }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>The Show Universe</title>
  <style>
    body {
      margin: 0;
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background-color: #0b1f2c;
      color: #ffffff;
      text-align: center;
      padding: 40px 20px;
    }
    .logo-container {
      display: flex;
      justify-content: center;
      gap: 20px;
      margin-bottom: 10px;
    }
    .logo-img {
      width: 120px;
      animation: shimmer 3s infinite;
    }
    .powered-text {
      font-size: 1.05em;
      margin: 8px 0 30px;
    }
    .pf-green { color: #00ff66; font-weight: bold; }
    .mc-green { color: #aaff99; font-weight: bold; }
    @keyframes shimmer {
      0% { opacity: 0.85; }
      50% { opacity: 1; }
      100% { opacity: 0.85; }
    }
    .rgb-line {
      height: 7px;
      width: 80%;
      max-width: 800px;
      margin: 10px auto 40px;
      border-radius: 10px;
      background: linear-gradient(270deg, #ff0000, #ff9900, #33ff33, #00ccff, #9933ff);
      background-size: 1000% 1000%;
      animation: rainbow 12s linear infinite;
    }
    @keyframes rainbow {
      0% { background-position: 0% 50%; }
      50% { background-position: 100% 50%; }
      100% { background-position: 0% 50%; }
    }
    .soap-list {
      display: flex;
      flex-wrap: wrap;
      justify-content: center;
      gap: 15px 20px;
    }
    /* New styles for pill-shaped button links */
    .soap-button {
      display: inline-flex;
      align-items: center;
      gap: 12px;
      background-color: #122e42;
      color: #cdefff;
      padding: 10px 25px;
      border-radius: 999px; /* This creates the pill shape */
      text-decoration: none;
      font-weight: bold;
      font-size: 1.1em;
      transition: transform 0.2s ease, box-shadow 0.2s ease, background-color 0.2s ease;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
      border: 1px solid #1f425b;
    }
    .soap-button:hover {
      transform: translateY(-3px) scale(1.03);
      box-shadow: 0 6px 20px rgba(0, 204, 255, 0.2);
      background-color: #1a3b58;
      color: #ffffff;
    }
    .soap-button img {
      width: 32px;
      height: 32px;
      border-radius: 50%; /* Circular logo */
      object-fit: cover;
      border: 2px solid #3a6c8e;
    }
    .no-soaps {
      background-color: rgba(0,0,0,0.2);
      padding: 20px;
      border-radius: 12px;
      color: #a0c0e0;
    }
    footer {
      margin-top: 50px;
      font-size: 0.85em;
      color: #888;
    }
  </style>
</head>
<body>

  <div class="logo-container">
    <img src="logo.png" alt="PressureFork Logo" class="logo-img">
    <img src="logo2.png" alt="MrCool3456 Logo" class="logo-img">
  </div>

  <div class="powered-text">
    Powered by <span class="pf-green">PressureFork</span> and <span class="mc-green">MrCool3456</span>
  </div>

  <div class="rgb-line"></div>

  <div class="soap-list">
    <?php if (empty($soaps)): ?>
      <p class="no-soaps">There are currently no published shows available.</p>
    <?php else: ?>
      <?php foreach ($soaps as $soap): ?>
        <a class="soap-button" href="<?= htmlspecialchars($admin_script_name) ?>?view=public&soap_id=<?= urlencode($soap['id']) ?>">
          <?php if (!empty($soap['logo'])): ?>
            <img src="<?= htmlspecialchars($soap['logo']) ?>" alt="">
          <?php endif; ?>
          <span><?= htmlspecialchars($soap['name']) ?></span>
        </a>
      <?php endforeach; ?>
    <?php endif; ?>
  </div>

  <footer>
    &copy; <?= date('Y') ?> PressureFork & MrCool3456. All rights reserved.
  </footer>

</body>
</html>
