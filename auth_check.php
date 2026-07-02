<?php
session_start();

// Check if this is an admin page requiring authentication
$currentScript = basename($_SERVER['PHP_SELF']);
// Bug #12 fix: Added 'app_admin.php' and 'proxy_admin.php' to the admin pages
// list so they get the admin_logged_in redirect (defense-in-depth).
// Also added 'pfp_admin.php' for the profile picture moderation page.
$adminPages = ['admin.php', 'account_admin.php', 'ban_admin.php', 'game_admin.php', 'app_admin.php', 'proxy_admin.php', 'popup_admin.php', 'pfp_admin.php', 'profile_admin.php', 'user_report_admin.php', 'admin_tools.php'];

if (in_array($currentScript, $adminPages)) {
  // Admin pages require authentication
  if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    header('Location: /admin_login.php');
    exit;
  }
} else {
  // Regular pages - no login required
  if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    $_SESSION['logged_in'] = true;
    $_SESSION['username'] = 'guest';
    $_SESSION['account_key'] = 'guest';
  }
}

if (file_exists(__DIR__ . '/profile_helpers.php')) {
  require_once __DIR__ . '/profile_helpers.php';
  // Only track online if not a guest user
  if (isset($_SESSION['account_key']) && $_SESSION['account_key'] !== 'guest') {
    profile_touch_online();
  }
}

// 500 fix: Defensive polyfills — if profile_helpers.php is an OLD version
// that doesn't define the CSRF functions, define them here so admin pages
// don't crash with "Call to undefined function profile_csrf_token()".
if (!function_exists('profile_csrf_token')) {
  function profile_csrf_token() {
    if (session_status() !== PHP_SESSION_ACTIVE) @session_start();
    if (empty($_SESSION['csrf_token'])) {
      $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
  }
}
if (!function_exists('profile_csrf_verify')) {
  function profile_csrf_verify() {
    if (session_status() !== PHP_SESSION_ACTIVE) @session_start();
    $expected = $_SESSION['csrf_token'] ?? '';
    $received = $_POST['csrf_token'] ?? '';
    if ($expected === '' || !hash_equals($expected, $received)) {
      http_response_code(403);
      echo 'CSRF token validation failed.';
      exit;
    }
    return true;
  }
}
?>
