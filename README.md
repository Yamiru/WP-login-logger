# 🛡️ WP Login Logger

*A comprehensive WordPress plugin for tracking and monitoring all user login activities with advanced features including IP geolocation, role detection, and privilege tracking.*

---

## 💾 Download the Plugin

⬇️ **[Click here to download the latest version (ZIP)](https://github.com/Yamiru/WP-login-logger/archive/refs/heads/main.zip)**

> You can also install it manually using Git or upload the ZIP through the WordPress admin panel.

---

## 📋 Features

### 🔹 Core Functionality
- **Complete User Tracking** – Monitors *all* users, not just administrators  
- **Login Event Types** – Tracks successful logins, failed attempts, and logouts  
- **User Role Detection** – Records user roles and permission levels  
- **Privilege Tracking** – Identifies users with administrative capabilities  
- **IP Geolocation** – Automatically detects country based on IP address  
- **Browser Detection** – Captures user agent information  
- **Path Tracking** – Records the URL path used for login  

### 🔐 Security Features
- **SQL Injection Protection** – Uses WordPress prepared statements  
- **XSS Prevention** – Full input/output sanitization and escaping  
- **Direct Access Protection** – Blocks unauthorized file access via `.htaccess` and PHP checks  
- **Secure IP Detection** – Validates and sanitizes IP addresses from headers  
- **Permission Checks** – Log access restricted to administrators only  

### ⚙️ Performance Optimizations
- **Indexed Database** – Optimized table structure for fast queries on large datasets  
- **Automatic Cleanup** – Keeps only the last 5,000 logs to prevent bloat  
- **Caching System** – Caches geolocation results for 7 days to reduce API load  
- **Pagination** – Displays 50 logs per page for smooth navigation  
- **Singleton Pattern** – Memory-efficient architecture  

### 🖥️ Admin Interface
- **Statistics Dashboard** – Visual overview of login metrics (success/failure rates, top countries, etc.)  
- **Advanced Filtering** – Filter logs by action type, user role, privileges, or search by username/IP  
- **Color-Coded Actions** – Clear visual indicators: green (success), red (failed), gray (logout)  
- **Responsive Design** – Fully functional on desktop, tablet, and mobile  
- **Export Ready** – Clean, structured data format suitable for CSV export or external analysis  

---


## Screenshot
![Imgur Image](https://i.imgur.com/iW1h9UB.png)

## 🚀 Installation

### Method 1: Direct Upload
1. [Download the plugin ZIP](https://github.com/Yamiru/WP-login-logger/archive/refs/heads/main.zip)  
2. Create a folder named `wp-login-logger` in `/wp-content/plugins/`  
3. Upload all files into the folder  
4. Activate the plugin via **WordPress Admin → Plugins**

---

### Method 2: ZIP Upload
1. Go to **WordPress Admin → Plugins → Add New → Upload Plugin**  
2. Upload the downloaded ZIP file  
3. Click **"Install Now"**, then **"Activate"**

---

### Method 3: Manual Installation (via Git)
```bash
cd /path/to/wordpress/wp-content/plugins/
git clone https://github.com/Yamiru/WP-login-logger.git wp-login-logger
