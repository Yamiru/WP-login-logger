
=== WP Login Logger ===
Contributors: yamiru
Tags: login, logger, security, audit, users, admin
Requires at least: 5.8
Tested up to: 6.6
Requires PHP: 7.4
Stable tag: 1.0.1
License: GPLv3 or later
License URI: https://www.gnu.org/licenses/gpl-3.0.html

A lightweight, privacy-conscious login tracking tool that records user logins and logouts with IP address, country (via public API), role, and admin privilege.

== Description ==

WP Login Logger records successful logins and logouts for all users and displays the data in an admin page with pagination. Logged fields include:

* User ID, username, email
* Role and whether the user has administrative capabilities
* Action (login / logout)
* IP address and country (with 7‑day transient cache)
* User agent (truncated for safety)
* Path where the login happened
* Login time and date

The plugin uses prepared statements and sanitization/escaping on input/output. Country lookups are cached via the WordPress Transients API to reduce remote calls.

**Privacy:** The plugin stores IP addresses and user agents in your WordPress database. Please disclose this in your site's privacy policy if required by your jurisdiction.

== Installation ==

1. Upload the plugin folder `wp-login-logger` to the `/wp-content/plugins/` directory, or install via the WordPress admin.
2. Activate the plugin through the 'Plugins' screen.
3. Go to **Users → Login Logs** to view entries.

== Frequently Asked Questions ==

= Does it track failed logins? =
No. This plugin tracks successful logins and explicit logouts. Failed logins can be monitored by security plugins like Limit Login Attempts, Wordfence, or your server logs.

= Where is data stored? =
Entries are stored in a custom database table `{{ $wpdb->prefix }}wp_login_logger` created on activation.

= Does it call external services? =
Only for optional geolocation lookups by IP. Results are cached for 7 days using transients. If a lookup fails, the country is saved as "Unknown".

= Can I export the logs? =
You can export via phpMyAdmin or a database tool. CSV export from the admin table can be added in a future release.

== Screenshots ==

1. Admin table showing login entries with pagination.

== Changelog ==

= 1.0.1 =
* Standardized plugin folder structure and main file name.
* Added i18n setup (`load_plugin_textdomain`) and `/languages` directory.
* Created `readme.txt` compliant with WordPress.org standards.
* Bumped version to 1.0.1 and clarified license field.

= 1.0.0 =
* Initial release.

== Upgrade Notice ==

= 1.0.1 =
This update reorganizes files and adds translation loading. Please ensure you replace the entire plugin folder.

== Plugin URI ==
https://github.com/Yamiru/WP-login-logger
