<?php
/*
Plugin Name: Simple Login Security
Description: Lightweight TOTP 2FA for wp-login. Includes modal setup with QR and one-time backup codes.
Version: 1.3.0
Author: luuhung93
Author URI: https://github.com/luuhung93/WP-Simple-Login-Security
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Text Domain: simple-login-security
Domain Path: /languages
*/

if (!defined('ABSPATH')) {
    exit;
}

define('SIMPLE_LOGIN_SECURITY_FILE', __FILE__);

require_once plugin_dir_path(__FILE__) . 'includes/class-simple-login-security-totp.php';
require_once plugin_dir_path(__FILE__) . 'includes/trait-simple-login-security-login-turnstile.php';
require_once plugin_dir_path(__FILE__) . 'includes/trait-simple-login-security-settings.php';
require_once plugin_dir_path(__FILE__) . 'includes/trait-simple-login-security-profile-ui.php';
require_once plugin_dir_path(__FILE__) . 'includes/trait-simple-login-security-ajax.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-simple-login-security-plugin.php';

Simple_Login_Security_Plugin::bootstrap();
