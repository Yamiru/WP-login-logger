<?php
/**
 * Plugin Name: WP Login Logger
 * Plugin URI: https://github.com/Yamiru/WP-login-logger
 * Description: Comprehensive login tracking system for all WordPress users with IP geolocation and role detection
 * Version: 1.0.0
 * Author: Yamiru
 * Author URI: https://github.com/Yamiru
 * License: GPL v3 or later
 * Text Domain: wp-login-logger
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Main plugin class
 */
class WPLoginLogger {
    
    private static $instance = null;
    private $table_name;
    private $max_logs = 5000;
    private $plugin_version = '1.0.0';
    private $db_version = '2.0';
    
    /**
     * Singleton pattern implementation
     */
    public static function getInstance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    /**
     * Constructor
     */
    private function __construct() {
        global $wpdb;
        $this->table_name = $wpdb->prefix . 'wp_login_logs';
        $this->initHooks();
    }
    
    /**
     * Initialize WordPress hooks
     */
    private function initHooks() {
        // Core login hooks for ALL users
        add_action('wp_login', array($this, 'logSuccessfulLogin'), 10, 2);
        add_action('wp_login_failed', array($this, 'logFailedLogin'));
        add_action('wp_logout', array($this, 'logLogout'));
        
        // Admin menu
        add_action('admin_menu', array($this, 'addAdminMenu'));
        
        // Cleanup old logs (optimization)
        add_action('wp_login_logger_cleanup', array($this, 'cleanupOldLogs'));
        
        // Enqueue admin styles
        add_action('admin_enqueue_scripts', array($this, 'enqueueAdminStyles'));
        
        // AJAX handler for country lookup
        add_action('wp_ajax_lookup_country', array($this, 'ajaxLookupCountry'));
    }
    
    /**
     * Log successful login for ALL users
     */
    public function logSuccessfulLogin($user_login, $user) {
        $this->insertLog(array(
            'user_id' => $user->ID,
            'username' => $user_login,
            'user_email' => $user->user_email,
            'user_role' => $this->getUserRole($user),
            'has_privileges' => $this->hasPrivileges($user),
            'action' => 'login_success',
            'ip_address' => $this->getClientIp(),
            'country' => $this->getCountryByIp($this->getClientIp()),
            'user_agent' => $this->sanitizeUserAgent(),
            'login_path' => $this->getCurrentPath()
        ));
    }
    
    /**
     * Log failed login attempt
     */
    public function logFailedLogin($username) {
        $this->insertLog(array(
            'user_id' => 0,
            'username' => $username,
            'user_email' => '',
            'user_role' => 'unknown',
            'has_privileges' => 0,
            'action' => 'login_failed',
            'ip_address' => $this->getClientIp(),
            'country' => $this->getCountryByIp($this->getClientIp()),
            'user_agent' => $this->sanitizeUserAgent(),
            'login_path' => $this->getCurrentPath()
        ));
    }
    
    /**
     * Log logout action for ALL users
     */
    public function logLogout() {
        $user = wp_get_current_user();
        if (!$user || !$user->ID) {
            return;
        }
        
        $this->insertLog(array(
            'user_id' => $user->ID,
            'username' => $user->user_login,
            'user_email' => $user->user_email,
            'user_role' => $this->getUserRole($user),
            'has_privileges' => $this->hasPrivileges($user),
            'action' => 'logout',
            'ip_address' => $this->getClientIp(),
            'country' => $this->getCountryByIp($this->getClientIp()),
            'user_agent' => $this->sanitizeUserAgent(),
            'login_path' => $this->getCurrentPath()
        ));
    }
    
    /**
     * Get user role
     */
    private function getUserRole($user) {
        if (!$user || !is_object($user)) {
            return 'none';
        }
        
        $roles = $user->roles;
        if (!empty($roles)) {
            return implode(', ', $roles);
        }
        
        return 'subscriber';
    }
    
    /**
     * Check if user has administrative privileges
     */
    private function hasPrivileges($user) {
        if (!$user || !is_object($user)) {
            return 0;
        }
        
        // Check for various admin capabilities
        $admin_caps = array(
            'manage_options',
            'edit_users',
            'delete_users',
            'create_users',
            'unfiltered_html',
            'edit_themes',
            'install_plugins',
            'update_plugins',
            'delete_plugins'
        );
        
        foreach ($admin_caps as $cap) {
            if (user_can($user, $cap)) {
                return 1;
            }
        }
        
        return 0;
    }
    
    /**
     * Get country by IP using free API
     */
    private function getCountryByIp($ip) {
        // Skip for local IPs
        if (in_array($ip, array('127.0.0.1', '::1', '0.0.0.0'))) {
            return 'Local';
        }
        
        // Try to get from transient cache first
        $cache_key = 'wll_country_' . md5($ip);
        $cached_country = get_transient($cache_key);
        
        if ($cached_country !== false) {
            return $cached_country;
        }
        
        // Use ip-api.com free service (no API key required)
        $api_url = "http://ip-api.com/json/{$ip}?fields=status,country,countryCode";
        
        $response = wp_remote_get($api_url, array(
            'timeout' => 2,
            'sslverify' => false
        ));
        
        if (!is_wp_error($response)) {
            $body = wp_remote_retrieve_body($response);
            $data = json_decode($body, true);
            
            if ($data && $data['status'] === 'success') {
                $country = $data['country'] . ' (' . $data['countryCode'] . ')';
                // Cache for 7 days
                set_transient($cache_key, $country, 7 * DAY_IN_SECONDS);
                return $country;
            }
        }
        
        return 'Unknown';
    }
    
    /**
     * Insert log entry with security measures
     */
    private function insertLog($data) {
        global $wpdb;
        
        // Prepare data with proper sanitization
        $insert_data = array(
            'user_id' => absint($data['user_id']),
            'username' => sanitize_text_field(substr($data['username'], 0, 60)),
            'user_email' => sanitize_email(substr($data['user_email'], 0, 100)),
            'user_role' => sanitize_text_field(substr($data['user_role'], 0, 100)),
            'has_privileges' => absint($data['has_privileges']),
            'action' => sanitize_text_field($data['action']),
            'ip_address' => sanitize_text_field(substr($data['ip_address'], 0, 45)),
            'country' => sanitize_text_field(substr($data['country'], 0, 100)),
            'user_agent' => sanitize_text_field(substr($data['user_agent'], 0, 255)),
            'login_path' => esc_url_raw(substr($data['login_path'], 0, 255)),
            'login_time' => current_time('mysql'),
            'login_date' => current_time('mysql', false)
        );
        
        // Use prepared statement for security
        $wpdb->insert(
            $this->table_name,
            $insert_data,
            array('%d', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s')
        );
        
        // Trigger cleanup if needed (optimization)
        $this->maybeScheduleCleanup();
    }
    
    /**
     * Get client IP address securely
     */
    private function getClientIp() {
        $ip = '';
        
        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $ip = $_SERVER['HTTP_CLIENT_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } elseif (!empty($_SERVER['REMOTE_ADDR'])) {
            $ip = $_SERVER['REMOTE_ADDR'];
        }
        
        // Validate IP
        $ip = filter_var($ip, FILTER_VALIDATE_IP);
        return $ip ? $ip : '0.0.0.0';
    }
    
    /**
     * Sanitize user agent string
     */
    private function sanitizeUserAgent() {
        if (isset($_SERVER['HTTP_USER_AGENT'])) {
            return sanitize_text_field($_SERVER['HTTP_USER_AGENT']);
        }
        return 'Unknown';
    }
    
    /**
     * Get current request path
     */
    private function getCurrentPath() {
        if (isset($_SERVER['REQUEST_URI'])) {
            return $_SERVER['REQUEST_URI'];
        }
        return '/';
    }
    
    /**
     * Add admin menu
     */
    public function addAdminMenu() {
        add_menu_page(
            'WP Login Logs',
            'Login Logs',
            'manage_options',
            'wp-login-logs',
            array($this, 'renderAdminPage'),
            'dashicons-shield-alt',
            99
        );
    }
    
    /**
     * Render admin page with logs table
     */
    public function renderAdminPage() {
        if (!current_user_can('manage_options')) {
            wp_die('You do not have sufficient permissions to access this page.');
        }
        
        global $wpdb;
        
        // Filter parameters
        $filter_action = isset($_GET['filter_action']) ? sanitize_text_field($_GET['filter_action']) : '';
        $filter_privileges = isset($_GET['filter_privileges']) ? sanitize_text_field($_GET['filter_privileges']) : '';
        $search_user = isset($_GET['search_user']) ? sanitize_text_field($_GET['search_user']) : '';
        
        // Pagination
        $per_page = 50;
        $current_page = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
        $offset = ($current_page - 1) * $per_page;
        
        // Build WHERE clause for filters
        $where_clauses = array();
        $where_values = array();
        
        if ($filter_action) {
            $where_clauses[] = 'action = %s';
            $where_values[] = $filter_action;
        }
        
        if ($filter_privileges !== '') {
            $where_clauses[] = 'has_privileges = %d';
            $where_values[] = intval($filter_privileges);
        }
        
        if ($search_user) {
            $where_clauses[] = '(username LIKE %s OR user_email LIKE %s)';
            $search_like = '%' . $wpdb->esc_like($search_user) . '%';
            $where_values[] = $search_like;
            $where_values[] = $search_like;
        }
        
        $where_sql = '';
        if (!empty($where_clauses)) {
            $where_sql = 'WHERE ' . implode(' AND ', $where_clauses);
        }
        
        // Get total count with filters
        if (!empty($where_values)) {
            $count_query = $wpdb->prepare(
                "SELECT COUNT(*) FROM {$this->table_name} {$where_sql}",
                $where_values
            );
        } else {
            $count_query = "SELECT COUNT(*) FROM {$this->table_name}";
        }
        
        $total_items = $wpdb->get_var($count_query);
        if ($total_items === null) {
            $total_items = 0;
        }
        
        // Get logs with pagination and filters
        $query_values = array_merge($where_values, array($per_page, $offset));
        
        if (!empty($where_values)) {
            $logs_query = $wpdb->prepare(
                "SELECT * FROM {$this->table_name} {$where_sql} ORDER BY login_time DESC LIMIT %d OFFSET %d",
                $query_values
            );
        } else {
            $logs_query = $wpdb->prepare(
                "SELECT * FROM {$this->table_name} ORDER BY login_time DESC LIMIT %d OFFSET %d",
                $per_page, $offset
            );
        }
        
        $logs = $wpdb->get_results($logs_query);
        
        if (!$logs) {
            $logs = array();
        }
        
        // Get statistics
        $total_logins = $wpdb->get_var("SELECT COUNT(*) FROM {$this->table_name} WHERE action = 'login_success'");
        $failed_logins = $wpdb->get_var("SELECT COUNT(*) FROM {$this->table_name} WHERE action = 'login_failed'");
        $privileged_logins = $wpdb->get_var("SELECT COUNT(*) FROM {$this->table_name} WHERE has_privileges = 1 AND action = 'login_success'");
        
        echo '<div class="wrap">';
        echo '<h1>WP Login Logger</h1>';
        
        // GitHub Links
        echo '<div class="wll-github-links">';
        echo '<a href="https://github.com/Yamiru/WP-login-logger" target="_blank" class="button"> View on GitHub</a> ';
        echo '<a href="https://github.com/Yamiru/WP-login-logger/issues" target="_blank" class="button"> Report Issue</a>';
        echo '</div>';
        
        // Statistics
        echo '<div class="wll-stats">';
        echo '<div class="wll-stat-box">';
        echo '<h3>Total Successful Logins</h3>';
        echo '<p class="wll-stat-number">' . number_format($total_logins) . '</p>';
        echo '</div>';
        echo '<div class="wll-stat-box">';
        echo '<h3>Failed Login Attempts</h3>';
        echo '<p class="wll-stat-number wll-failed">' . number_format($failed_logins) . '</p>';
        echo '</div>';
        echo '<div class="wll-stat-box">';
        echo '<h3>Privileged User Logins</h3>';
        echo '<p class="wll-stat-number wll-privileged">' . number_format($privileged_logins) . '</p>';
        echo '</div>';
        echo '<div class="wll-stat-box">';
        echo '<h3>Total Logs</h3>';
        echo '<p class="wll-stat-number">' . number_format($total_items) . '</p>';
        echo '</div>';
        echo '</div>';
        
        // Filters
        echo '<div class="wll-filters">';
        echo '<form method="get" action="">';
        echo '<input type="hidden" name="page" value="wp-login-logs">';
        
        echo '<select name="filter_action">';
        echo '<option value="">All Actions</option>';
        echo '<option value="login_success"' . selected($filter_action, 'login_success', false) . '>Successful Login</option>';
        echo '<option value="login_failed"' . selected($filter_action, 'login_failed', false) . '>Failed Login</option>';
        echo '<option value="logout"' . selected($filter_action, 'logout', false) . '>Logout</option>';
        echo '</select>';
        
        echo '<select name="filter_privileges">';
        echo '<option value="">All Users</option>';
        echo '<option value="1"' . selected($filter_privileges, '1', false) . '>With Privileges</option>';
        echo '<option value="0"' . selected($filter_privileges, '0', false) . '>Without Privileges</option>';
        echo '</select>';
        
        echo '<input type="text" name="search_user" placeholder="Search username or email..." value="' . esc_attr($search_user) . '">';
        
        echo '<input type="submit" class="button" value="Filter">';
        echo ' <a href="?page=wp-login-logs" class="button">Clear Filters</a>';
        echo '</form>';
        echo '</div>';
        
        // Logs table
        echo '<table class="wp-list-table widefat fixed striped">';
        echo '<thead>';
        echo '<tr>';
        echo '<th width="40">ID</th>';
        echo '<th>Username</th>';
        echo '<th>Email</th>';
        echo '<th>Role</th>';
        echo '<th width="80">Privileges</th>';
        echo '<th width="100">Action</th>';
        echo '<th>IP Address</th>';
        echo '<th>Country</th>';
        echo '<th>Path</th>';
        echo '<th>Date & Time</th>';
        echo '<th>User Agent</th>';
        echo '</tr>';
        echo '</thead>';
        echo '<tbody>';
        
        if (!empty($logs)) {
            foreach ($logs as $log) {
                echo '<tr>';
                echo '<td>' . esc_html($log->id) . '</td>';
                echo '<td>';
                echo '<strong>' . esc_html($log->username) . '</strong>';
                if ($log->user_id > 0) {
                    echo ' <small>(ID: ' . esc_html($log->user_id) . ')</small>';
                }
                echo '</td>';
                echo '<td>' . esc_html($log->user_email ? $log->user_email : '-') . '</td>';
                echo '<td>' . esc_html($log->user_role ? $log->user_role : 'none') . '</td>';
                echo '<td>';
                if ($log->has_privileges) {
                    echo '<span class="wll-badge wll-badge-admin">Admin</span>';
                } else {
                    echo '<span class="wll-badge wll-badge-user">User</span>';
                }
                echo '</td>';
                echo '<td>';
                echo '<span class="wll-action-badge wll-action-' . esc_attr($log->action) . '">';
                echo esc_html(ucwords(str_replace('_', ' ', $log->action)));
                echo '</span>';
                echo '</td>';
                echo '<td>' . esc_html($log->ip_address) . '</td>';
                echo '<td>' . esc_html($log->country ? $log->country : 'Loading...') . '</td>';
                echo '<td title="' . esc_attr($log->login_path) . '">';
                $path = $log->login_path;
                if (strlen($path) > 25) {
                    echo esc_html(substr($path, 0, 25)) . '...';
                } else {
                    echo esc_html($path);
                }
                echo '</td>';
                echo '<td>' . esc_html($log->login_time) . '</td>';
                echo '<td title="' . esc_attr($log->user_agent) . '">';
                $agent = $log->user_agent;
                if (strlen($agent) > 40) {
                    echo esc_html(substr($agent, 0, 40)) . '...';
                } else {
                    echo esc_html($agent);
                }
                echo '</td>';
                echo '</tr>';
            }
        } else {
            echo '<tr><td colspan="11">No logs found.</td></tr>';
        }
        
        echo '</tbody>';
        echo '</table>';
        
        // Pagination
        $total_pages = ceil($total_items / $per_page);
        if ($total_pages > 1) {
            $page_links = paginate_links(array(
                'base' => add_query_arg('paged', '%#%'),
                'format' => '',
                'prev_text' => '&laquo;',
                'next_text' => '&raquo;',
                'total' => $total_pages,
                'current' => $current_page
            ));
            
            if ($page_links) {
                echo '<div class="tablenav">';
                echo '<div class="tablenav-pages">';
                echo $page_links;
                echo '</div>';
                echo '</div>';
            }
        }
        
        echo '</div>';
    }
    
    /**
     * Enqueue admin styles
     */
    public function enqueueAdminStyles($hook) {
        if ('toplevel_page_wp-login-logs' !== $hook) {
            return;
        }
        
        wp_add_inline_style('wp-admin', '
            .wll-github-links { margin: 15px 0; }
            .wll-github-links .button { margin-right: 5px; }
            .wll-stats { display: flex; gap: 20px; margin: 20px 0; flex-wrap: wrap; }
            .wll-stat-box { background: #fff; padding: 20px; border: 1px solid #ccd0d4; flex: 0 0 200px; box-shadow: 0 1px 1px rgba(0,0,0,.04); }
            .wll-stat-box h3 { margin: 0 0 10px 0; color: #23282d; font-size: 14px; }
            .wll-stat-number { font-size: 32px; font-weight: 600; color: #0073aa; margin: 0; }
            .wll-stat-number.wll-failed { color: #dc3232; }
            .wll-stat-number.wll-privileged { color: #46b450; }
            .wll-filters { background: #fff; padding: 15px; margin: 20px 0; border: 1px solid #ccd0d4; }
            .wll-filters form { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
            .wll-filters select, .wll-filters input[type="text"] { min-width: 150px; }
            .wll-action-badge { padding: 3px 8px; border-radius: 3px; font-size: 12px; font-weight: 600; display: inline-block; }
            .wll-action-login_success { background: #d4edda; color: #155724; }
            .wll-action-login_failed { background: #f8d7da; color: #721c24; }
            .wll-action-logout { background: #d1ecf1; color: #0c5460; }
            .wll-badge { padding: 2px 6px; border-radius: 3px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
            .wll-badge-admin { background: #46b450; color: white; }
            .wll-badge-user { background: #0073aa; color: white; }
        ');
    }
    
    /**
     * Schedule cleanup if needed
     */
    private function maybeScheduleCleanup() {
        if (!wp_next_scheduled('wp_login_logger_cleanup')) {
            wp_schedule_event(time(), 'daily', 'wp_login_logger_cleanup');
        }
    }
    
    /**
     * Clean up old logs (optimization)
     */
    public function cleanupOldLogs() {
        global $wpdb;
        
        // Keep only the most recent logs
        $wpdb->query($wpdb->prepare(
            "DELETE FROM {$this->table_name} 
             WHERE id NOT IN (
                SELECT id FROM (
                    SELECT id FROM {$this->table_name} 
                    ORDER BY login_time DESC 
                    LIMIT %d
                ) AS recent
             )",
            $this->max_logs
        ));
    }
    
    /**
     * Create database table
     */
    public static function createTable() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'wp_login_logs';
        $charset_collate = $wpdb->get_charset_collate();
        
        $sql = "CREATE TABLE IF NOT EXISTS $table_name (
            id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            user_id bigint(20) UNSIGNED NOT NULL DEFAULT 0,
            username varchar(60) NOT NULL,
            user_email varchar(100) DEFAULT '',
            user_role varchar(100) DEFAULT '',
            has_privileges tinyint(1) NOT NULL DEFAULT 0,
            action varchar(20) NOT NULL,
            ip_address varchar(45) NOT NULL,
            country varchar(100) DEFAULT '',
            user_agent varchar(255) DEFAULT '',
            login_path varchar(255) DEFAULT '',
            login_time datetime DEFAULT CURRENT_TIMESTAMP,
            login_date date DEFAULT NULL,
            PRIMARY KEY (id),
            KEY user_id (user_id),
            KEY has_privileges (has_privileges),
            KEY action (action),
            KEY login_time (login_time),
            KEY ip_address (ip_address)
        ) $charset_collate;";
        
        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);
        
        update_option('wll_db_version', '2.0');
        
        // Schedule cleanup
        if (!wp_next_scheduled('wp_login_logger_cleanup')) {
            wp_schedule_event(time(), 'daily', 'wp_login_logger_cleanup');
        }
    }
    
    /**
     * Remove scheduled tasks
     */
    public static function deactivate() {
        wp_clear_scheduled_hook('wp_login_logger_cleanup');
    }
}

// Plugin activation
register_activation_hook(__FILE__, array('WPLoginLogger', 'createTable'));

// Plugin deactivation
register_deactivation_hook(__FILE__, array('WPLoginLogger', 'deactivate'));

// Initialize plugin when WordPress loads
add_action('plugins_loaded', function() {
    WPLoginLogger::getInstance();
});
