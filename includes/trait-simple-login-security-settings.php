<?php

if (!defined('ABSPATH')) {
    exit;
}

trait Simple_Login_Security_Settings_Trait {
    public function enqueue_settings_assets($hook_suffix) {
        if ($hook_suffix !== 'settings_page_simple-login-security') {
            return;
        }

        if (!current_user_can('manage_options')) {
            return;
        }

        $base_url = plugin_dir_url(SIMPLE_LOGIN_SECURITY_FILE) . 'assets/';
        $base_path = plugin_dir_path(SIMPLE_LOGIN_SECURITY_FILE) . 'assets/';

        wp_enqueue_style(
            'simple-login-security-admin',
            $base_url . 'admin.css',
            array(),
            $this->get_asset_version($base_path . 'admin.css')
        );

        wp_enqueue_script(
            'simple-login-security-turnstile-api',
            'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit',
            array(),
            null,
            true
        );

        wp_enqueue_script(
            'simple-login-security-settings',
            $base_url . 'settings.js',
            array('simple-login-security-turnstile-api'),
            $this->get_asset_version($base_path . 'settings.js'),
            true
        );

        wp_localize_script('simple-login-security-settings', 'SimpleLoginSecuritySettings', array(
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('simple_login_security_test_turnstile'),
            'i18n' => $this->get_settings_i18n_strings(),
        ));
    }

    public function register_settings_page() {
        add_options_page(
            __('Simple Login Security', 'simple-login-security'),
            __('Simple Login Security', 'simple-login-security'),
            'manage_options',
            'simple-login-security',
            array($this, 'render_settings_page')
        );
    }

    public function register_settings() {
        register_setting(
            'simple_login_security_settings',
            Simple_Login_Security_Plugin::OPTION_TURNSTILE_ENABLED,
            array($this, 'sanitize_checkbox')
        );
        register_setting(
            'simple_login_security_settings',
            Simple_Login_Security_Plugin::OPTION_TURNSTILE_SITE_KEY,
            'sanitize_text_field'
        );
        register_setting(
            'simple_login_security_settings',
            Simple_Login_Security_Plugin::OPTION_TURNSTILE_SECRET_KEY,
            'sanitize_text_field'
        );

        add_settings_section(
            'simple_login_security_turnstile_section',
            __('Cloudflare Turnstile', 'simple-login-security'),
            '__return_false',
            'simple-login-security'
        );

        add_settings_field(
            'simple_login_security_turnstile_enabled',
            __('Enable Turnstile on Login', 'simple-login-security'),
            array($this, 'render_turnstile_enabled_field'),
            'simple-login-security',
            'simple_login_security_turnstile_section'
        );
        add_settings_field(
            'simple_login_security_turnstile_site_key',
            __('Turnstile Site Key', 'simple-login-security'),
            array($this, 'render_turnstile_site_key_field'),
            'simple-login-security',
            'simple_login_security_turnstile_section'
        );
        add_settings_field(
            'simple_login_security_turnstile_secret_key',
            __('Turnstile Secret Key', 'simple-login-security'),
            array($this, 'render_turnstile_secret_key_field'),
            'simple-login-security',
            'simple_login_security_turnstile_section'
        );
        add_settings_field(
            'simple_login_security_turnstile_test',
            __('Turnstile Test', 'simple-login-security'),
            array($this, 'render_turnstile_test_field'),
            'simple-login-security',
            'simple_login_security_turnstile_section'
        );
    }

    public function render_settings_page() {
        if (!current_user_can('manage_options')) {
            return;
        }
        ?>
        <div class="wrap">
            <h1><?php esc_html_e('Simple Login Security Settings', 'simple-login-security'); ?></h1>
            <form method="post" action="options.php">
                <?php settings_fields('simple_login_security_settings'); ?>
                <?php do_settings_sections('simple-login-security'); ?>
                <?php submit_button(); ?>
            </form>
            <?php $this->render_turnstile_test_modal(); ?>
        </div>
        <?php
    }

    public function render_turnstile_enabled_field() {
        $enabled = get_option(Simple_Login_Security_Plugin::OPTION_TURNSTILE_ENABLED, '0') === '1';
        ?>
        <label>
            <input type="hidden" name="<?php echo esc_attr(Simple_Login_Security_Plugin::OPTION_TURNSTILE_ENABLED); ?>" value="0" />
            <input type="checkbox" name="<?php echo esc_attr(Simple_Login_Security_Plugin::OPTION_TURNSTILE_ENABLED); ?>" value="1" <?php checked($enabled); ?> />
            <?php esc_html_e('Require Turnstile challenge on wp-login.php before authentication.', 'simple-login-security'); ?>
        </label>
        <?php
    }

    public function render_turnstile_site_key_field() {
        $value = $this->get_turnstile_site_key();
        ?>
        <input type="text" class="regular-text" id="simple-login-security-turnstile-site-key" name="<?php echo esc_attr(Simple_Login_Security_Plugin::OPTION_TURNSTILE_SITE_KEY); ?>" value="<?php echo esc_attr($value); ?>" />
        <?php
    }

    public function render_turnstile_secret_key_field() {
        $value = $this->get_turnstile_secret_key();
        ?>
        <input type="password" class="regular-text" id="simple-login-security-turnstile-secret-key" name="<?php echo esc_attr(Simple_Login_Security_Plugin::OPTION_TURNSTILE_SECRET_KEY); ?>" value="<?php echo esc_attr($value); ?>" autocomplete="off" />
        <?php
    }

    public function render_turnstile_test_field() {
        ?>
        <button type="button" class="button" id="simple-login-security-test-turnstile">
            <?php esc_html_e('Open Turnstile Test', 'simple-login-security'); ?>
        </button>
        <p class="description">
            <?php esc_html_e('Use current Site Key and Secret Key values to run a live Turnstile verification test in a popup.', 'simple-login-security'); ?>
        </p>
        <?php
    }

    public function ajax_test_turnstile() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Not allowed.', 'simple-login-security')), 403);
        }

        $nonce = isset($_POST['nonce']) ? sanitize_text_field(wp_unslash($_POST['nonce'])) : '';
        if (!wp_verify_nonce($nonce, 'simple_login_security_test_turnstile')) {
            wp_send_json_error(array('message' => __('Invalid security token.', 'simple-login-security')), 403);
        }

        $token = isset($_POST['token']) ? sanitize_text_field(wp_unslash($_POST['token'])) : '';
        $secret_key = isset($_POST['secretKey']) ? sanitize_text_field(wp_unslash($_POST['secretKey'])) : '';

        if ($token === '' || $secret_key === '') {
            wp_send_json_error(array('message' => __('Missing token or secret key.', 'simple-login-security')), 400);
        }

        if (!$this->verify_turnstile_token_with_secret($token, $secret_key)) {
            wp_send_json_error(array('message' => __('Turnstile verification failed. Check Site Key/Secret Key and try again.', 'simple-login-security')), 400);
        }

        wp_send_json_success(array('message' => __('Turnstile verification passed.', 'simple-login-security')));
    }

    public function sanitize_checkbox($value) {
        return $value ? '1' : '0';
    }

    private function render_turnstile_test_modal() {
        ?>
        <div class="simple-login-security-modal" id="simple-login-security-turnstile-modal" hidden>
            <div class="simple-login-security-modal__backdrop" data-close="1"></div>
            <div class="simple-login-security-modal__card" role="dialog" aria-modal="true" aria-labelledby="simple-login-security-turnstile-modal-title">
                <button type="button" class="simple-login-security-modal__close" id="simple-login-security-turnstile-close" aria-label="<?php esc_attr_e('Close', 'simple-login-security'); ?>">&times;</button>
                <h3 id="simple-login-security-turnstile-modal-title"><?php esc_html_e('Turnstile Live Test', 'simple-login-security'); ?></h3>
                <p><?php esc_html_e('Complete the challenge below. The plugin will verify the token with the Secret Key you entered.', 'simple-login-security'); ?></p>
                <div id="simple-login-security-turnstile-widget"></div>
                <p id="simple-login-security-turnstile-message" class="simple-login-security-message"></p>
            </div>
        </div>
        <?php
    }

    private function get_settings_i18n_strings() {
        return array(
            'missingKeys' => __('Please enter both Turnstile Site Key and Secret Key.', 'simple-login-security'),
            'loading' => __('Loading challenge...', 'simple-login-security'),
            'verifying' => __('Verifying challenge...', 'simple-login-security'),
            'success' => __('Turnstile test passed.', 'simple-login-security'),
            'error' => __('Turnstile test failed. Please try again.', 'simple-login-security'),
            'loadError' => __('Unable to load Turnstile script. Refresh and try again.', 'simple-login-security'),
            'expired' => __('Challenge expired. Please complete it again.', 'simple-login-security'),
        );
    }
}
