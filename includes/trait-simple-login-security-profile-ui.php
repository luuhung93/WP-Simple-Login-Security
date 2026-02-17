<?php

if (!defined('ABSPATH')) {
    exit;
}

trait Simple_Login_Security_Profile_UI_Trait {
    public function enqueue_admin_assets($hook_suffix) {
        if ($hook_suffix !== 'profile.php' && $hook_suffix !== 'user-edit.php') {
            return;
        }

        $target_user_id = $this->get_profile_target_user_id();
        if (!$target_user_id || !current_user_can('edit_user', $target_user_id)) {
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
            'simple-login-security-qrcode',
            $base_url . 'jquery.qrcode.min.js',
            array('jquery'),
            $this->get_asset_version($base_path . 'jquery.qrcode.min.js'),
            true
        );

        wp_enqueue_script(
            'simple-login-security-admin',
            $base_url . 'admin.js',
            array('jquery', 'simple-login-security-qrcode'),
            $this->get_asset_version($base_path . 'admin.js'),
            true
        );

        wp_localize_script('simple-login-security-admin', 'SimpleLoginSecurity', array(
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'userId' => $target_user_id,
            'nonce' => wp_create_nonce($this->get_manage_nonce_action($target_user_id)),
            'i18n' => $this->get_admin_i18n_strings(),
        ));
    }

    public function render_profile_panel($user) {
        if (!($user instanceof WP_User) || !current_user_can('edit_user', $user->ID)) {
            return;
        }

        $enabled = $this->is_enabled_for_user($user->ID);
        $remaining = $this->count_backup_codes($user->ID);
        ?>
        <h2><?php esc_html_e('Simple Login Security', 'simple-login-security'); ?></h2>
        <table class="form-table" role="presentation">
            <?php $this->render_profile_status_row($enabled); ?>
            <?php $this->render_profile_backup_row($remaining); ?>
            <?php $this->render_profile_actions_row($enabled); ?>
        </table>

        <?php $this->render_setup_modal(); ?>
        <?php
    }

    private function render_profile_status_row($enabled) {
        ?>
        <tr>
            <th><?php esc_html_e('Status', 'simple-login-security'); ?></th>
            <td>
                <strong id="simple-login-security-status-text"><?php echo $enabled ? esc_html__('Enabled', 'simple-login-security') : esc_html__('Disabled', 'simple-login-security'); ?></strong>
                <p class="description"><?php esc_html_e('2FA is required at wp-login for this user when enabled.', 'simple-login-security'); ?></p>
            </td>
        </tr>
        <?php
    }

    private function render_profile_backup_row($remaining) {
        ?>
        <tr>
            <th><?php esc_html_e('Backup codes', 'simple-login-security'); ?></th>
            <td>
                <span id="simple-login-security-backup-count"><?php echo esc_html((string) $remaining); ?></span>
                <span><?php esc_html_e('codes remaining', 'simple-login-security'); ?></span>
            </td>
        </tr>
        <?php
    }

    private function render_profile_actions_row($enabled) {
        ?>
        <tr>
            <th><?php esc_html_e('Actions', 'simple-login-security'); ?></th>
            <td>
                <button type="button" class="button button-primary" id="simple-login-security-open-setup">
                    <?php echo $enabled ? esc_html__('Reconfigure 2FA', 'simple-login-security') : esc_html__('Enable 2FA', 'simple-login-security'); ?>
                </button>
                <button type="button" class="button" id="simple-login-security-regen-backups" <?php disabled(!$enabled); ?>>
                    <?php esc_html_e('Regenerate backup codes', 'simple-login-security'); ?>
                </button>
                <button type="button" class="button" id="simple-login-security-disable" <?php disabled(!$enabled); ?>>
                    <?php esc_html_e('Disable 2FA', 'simple-login-security'); ?>
                </button>
            </td>
        </tr>
        <?php
    }

    private function render_setup_modal() {
        ?>
        <div class="simple-login-security-modal" id="simple-login-security-modal" hidden>
            <div class="simple-login-security-modal__backdrop" data-close="1"></div>
            <div class="simple-login-security-modal__card" role="dialog" aria-modal="true" aria-labelledby="simple-login-security-modal-title">
                <button type="button" class="simple-login-security-modal__close" id="simple-login-security-close" aria-label="Close">&times;</button>
                <h3 id="simple-login-security-modal-title"><?php esc_html_e('Set up Two-Factor Authentication', 'simple-login-security'); ?></h3>

                <div id="simple-login-security-setup-step">
                    <p class="simple-login-security-warning">
                        <?php esc_html_e('Warning: This setup replaces the previous secret. Old authenticator devices will no longer generate valid codes.', 'simple-login-security'); ?>
                    </p>
                    <p><?php esc_html_e('1) Scan this QR code in your authenticator app.', 'simple-login-security'); ?></p>
                    <div id="simple-login-security-qr" aria-label="QR"></div>
                    <p><?php esc_html_e('2) If needed, enter this secret manually:', 'simple-login-security'); ?></p>
                    <p><code id="simple-login-security-secret"></code></p>
                    <p><?php esc_html_e('3) Enter the 6-digit code to verify setup.', 'simple-login-security'); ?></p>
                    <input type="text" id="simple-login-security-otp" class="regular-text" inputmode="numeric" maxlength="6" />
                    <p>
                        <button type="button" class="button button-primary" id="simple-login-security-verify"><?php esc_html_e('Verify and Enable', 'simple-login-security'); ?></button>
                    </p>
                </div>

                <div id="simple-login-security-backup-step" hidden>
                    <p><strong><?php esc_html_e('Backup codes (show once)', 'simple-login-security'); ?></strong></p>
                    <p><?php esc_html_e('Use each code once if you cannot access your authenticator app.', 'simple-login-security'); ?></p>
                    <p>
                        <button type="button" class="button" id="simple-login-security-copy-backups"><?php esc_html_e('Copy backup codes', 'simple-login-security'); ?></button>
                    </p>
                    <ul id="simple-login-security-backup-list"></ul>
                </div>

                <p id="simple-login-security-message" class="simple-login-security-message"></p>
            </div>
        </div>
        <?php
    }

    private function get_admin_i18n_strings() {
        return array(
            'loading' => __('Loading...', 'simple-login-security'),
            'error' => __('Something went wrong. Please try again.', 'simple-login-security'),
            'otpPlaceholder' => __('Enter 6-digit code', 'simple-login-security'),
            'setupSuccess' => __('2FA is enabled. Save backup codes now.', 'simple-login-security'),
            'regenSuccess' => __('New backup codes generated.', 'simple-login-security'),
            'disableConfirm' => __('Disable 2FA for this account?', 'simple-login-security'),
            'enabledText' => __('Enabled', 'simple-login-security'),
            'disabledText' => __('Disabled', 'simple-login-security'),
            'copySuccess' => __('Backup codes copied.', 'simple-login-security'),
            'copyError' => __('Cannot copy automatically. Please copy manually.', 'simple-login-security'),
        );
    }

    private function get_asset_version($path) {
        return (string) filemtime($path);
    }

    private function get_profile_target_user_id() {
        if (isset($_GET['user_id'])) {
            return absint(wp_unslash($_GET['user_id']));
        }

        $current_id = get_current_user_id();
        return $current_id > 0 ? $current_id : 0;
    }
}
