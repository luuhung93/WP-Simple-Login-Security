<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Simple_Login_Security_Plugin {
    use Simple_Login_Security_Login_Turnstile_Trait;
    use Simple_Login_Security_Settings_Trait;
    use Simple_Login_Security_Profile_UI_Trait;
    use Simple_Login_Security_Ajax_Trait;

    public const META_ENABLED = 'simple_login_security_enabled';
    public const META_SECRET = 'simple_login_security_secret';
    public const META_LAST_COUNTER = 'simple_login_security_last_counter';
    public const META_PENDING_SECRET = 'simple_login_security_pending_secret';
    public const META_PENDING_CREATED = 'simple_login_security_pending_created';
    public const META_BACKUP_CODES = 'simple_login_security_backup_codes';
    public const PENDING_TTL = 900;
    public const LOGIN_OTP_TTL = 300;
    public const LOGIN_OTP_TRANSIENT_PREFIX = 'simple_login_security_login_otp_';
    public const OPTION_TURNSTILE_ENABLED = 'simple_login_security_turnstile_enabled';
    public const OPTION_TURNSTILE_SITE_KEY = 'simple_login_security_turnstile_site_key';
    public const OPTION_TURNSTILE_SECRET_KEY = 'simple_login_security_turnstile_secret_key';

    private $totp;

    public static function bootstrap() {
        static $instance = null;
        if ($instance === null) {
            $instance = new self(new Simple_Login_Security_TOTP());
        }
        return $instance;
    }

    private function __construct(Simple_Login_Security_TOTP $totp) {
        $this->totp = $totp;

        add_action('login_form', array($this, 'render_login_field'));
        add_action('login_form_simple_login_security_otp', array($this, 'handle_login_otp_challenge'));
        add_action('login_enqueue_scripts', array($this, 'enqueue_login_assets'));
        add_filter('authenticate', array($this, 'validate_turnstile_login'), 15, 3);
        add_filter('authenticate', array($this, 'validate_login_otp'), 40, 3);

        add_action('show_user_profile', array($this, 'render_profile_panel'));
        add_action('edit_user_profile', array($this, 'render_profile_panel'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_assets'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_settings_assets'));
        add_action('admin_menu', array($this, 'register_settings_page'));
        add_action('admin_init', array($this, 'register_settings'));

        add_action('wp_ajax_simple_login_security_start_setup', array($this, 'ajax_start_setup'));
        add_action('wp_ajax_simple_login_security_confirm_setup', array($this, 'ajax_confirm_setup'));
        add_action('wp_ajax_simple_login_security_regenerate_backup', array($this, 'ajax_regenerate_backup_codes'));
        add_action('wp_ajax_simple_login_security_disable', array($this, 'ajax_disable_2fa'));
        add_action('wp_ajax_simple_login_security_test_turnstile', array($this, 'ajax_test_turnstile'));
    }

    private function is_enabled_for_user($user_id) {
        return get_user_meta($user_id, self::META_ENABLED, true) === '1';
    }

    private function generate_backup_codes() {
        $codes = array();

        for ($i = 0; $i < 9; $i++) {
            $raw = strtoupper(bin2hex(random_bytes(4)));
            $codes[] = substr($raw, 0, 4) . '-' . substr($raw, 4, 4);
        }

        return $codes;
    }

    private function store_backup_codes($user_id, array $codes) {
        $hashed = array();

        foreach ($codes as $code) {
            $normalized = $this->normalize_backup_code($code);
            $hashed[] = wp_hash_password($normalized);
        }

        update_user_meta($user_id, self::META_BACKUP_CODES, $hashed);
    }

    private function consume_backup_code($user_id, $input) {
        $normalized = $this->normalize_backup_code($input);
        if ($normalized === '') {
            return false;
        }

        $hashes = get_user_meta($user_id, self::META_BACKUP_CODES, true);
        if (!is_array($hashes) || empty($hashes)) {
            return false;
        }

        foreach ($hashes as $index => $hash) {
            if (is_string($hash) && wp_check_password($normalized, $hash)) {
                unset($hashes[$index]);
                update_user_meta($user_id, self::META_BACKUP_CODES, array_values($hashes));
                return true;
            }
        }

        return false;
    }

    private function count_backup_codes($user_id) {
        $hashes = get_user_meta($user_id, self::META_BACKUP_CODES, true);
        return is_array($hashes) ? count($hashes) : 0;
    }

    private function normalize_backup_code($code) {
        return strtoupper(preg_replace('/[^A-Z0-9]/', '', (string) $code));
    }
}
