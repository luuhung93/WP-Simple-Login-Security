=== Simple Login Security ===
Contributors: luuhung93
Tags: 2fa, two-factor authentication, login security, otp, totp, turnstile
Requires at least: 6.0
Tested up to: 6.9
Requires PHP: 7.4
Stable tag: 1.3.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Lightweight two-factor authentication for WordPress login with optional Cloudflare Turnstile.

== Description ==

Simple Login Security adds TOTP-based 2FA to WordPress login with a clean two-step flow.

Features:
- Two-step login flow
- Step 1: username/password (+ optional Turnstile)
- Step 2: OTP or backup code (only when user has 2FA enabled)
- Profile modal setup with QR code and manual secret
- OTP verification before activation
- 9 backup codes per generation
- Regenerate backup codes (old codes are invalid immediately)
- Copy backup codes button
- Turnstile settings page with live verification popup
- Reconfigure warning when replacing existing secret

== Installation ==

1. Upload the plugin folder to `/wp-content/plugins/simple-login-security/`.
2. Activate the plugin through the Plugins menu in WordPress.
3. (Optional) Configure Turnstile in Settings -> Simple Login Security.
4. Go to Users -> Profile and click Enable 2FA.
5. Scan QR code, verify OTP, and store backup codes safely.

== Frequently Asked Questions ==

= If a user has not enabled 2FA, do they need OTP? =

No. They login normally with username and password (plus Turnstile if enabled).

= What happens when I regenerate backup codes? =

A new set is created and all old backup codes are invalid immediately.

= What happens when I reconfigure 2FA? =

A new secret is generated. Old authenticator entries/devices will stop working.

== Screenshots ==

1. 2FA setup popup with QR and verification (`screenshot-1.png`).
2. Login form with Turnstile enabled (`screenshot-2.png`).

== Changelog ==

= 1.3.0 =
* Switched login to two-step flow: OTP screen is shown only for users with 2FA enabled.
* Added Turnstile live test popup on Settings page.
* Improved wp-login layout compatibility when Turnstile is enabled.
* Updated documentation and screenshots.

= 1.2.0 =
* Renamed plugin to Simple Login Security.
* Added optional Cloudflare Turnstile on login.
* Refactored plugin into class and trait files.

= 1.1.0 =
* Added setup modal with QR flow.
* Added one-time backup codes and regenerate action.
* Added copy backup codes button.

= 1.0.0 =
* Initial release.
