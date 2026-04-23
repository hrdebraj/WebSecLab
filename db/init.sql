-- ============================================================
-- WebSecLab - Database Initialisation
-- Intentionally vulnerable. Do NOT deploy outside lab.
-- ============================================================

CREATE DATABASE IF NOT EXISTS weblab CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE weblab;

-- ------------------------------------------------------------
-- Users table (used by 2nd-order SQLi and Blind SQLi)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    username     VARCHAR(120) NOT NULL UNIQUE,
    password     VARCHAR(200) NOT NULL,
    email        VARCHAR(200) DEFAULT '',
    role         VARCHAR(30)  DEFAULT 'user',
    api_key      VARCHAR(200) DEFAULT '',
    private_note TEXT
);

INSERT INTO users (username, password, email, role, api_key, private_note) VALUES
 ('admin',   'S3cretAdminPass!2026', 'admin@lab.local',   'admin', 'FLAG{blind_boolean_admin_pwn}',     'FLAG{2nd_order_admin_reset_success}'),
 ('alice',   'alice123',             'alice@lab.local',   'user',  'ak_alice_7f2a',                     'Reminder: renew TLS cert.'),
 ('bob',     'qwerty',               'bob@lab.local',     'user',  'ak_bob_9c1b',                       'TODO: write unit tests.'),
 ('charlie', 'letmein',              'charlie@lab.local', 'user',  'ak_charlie_3e4d',                   'Nothing to see here.');

-- ------------------------------------------------------------
-- Comments table (2nd-order SQLi Level 2)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS comments (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    author     VARCHAR(120) NOT NULL,
    content    TEXT,
    flagged    TINYINT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO comments (author, content) VALUES
 ('alice', 'Great product!'),
 ('bob',   'Shipping was fast.');

-- ------------------------------------------------------------
-- Password reset tokens (2nd-order SQLi Level 3)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reset_tokens (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    email      VARCHAR(200) NOT NULL,
    token      VARCHAR(80)  NOT NULL,
    used       TINYINT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ------------------------------------------------------------
-- Products table (Blind SQLi Level 2 - time based)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS products (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    name        VARCHAR(120),
    category    VARCHAR(80),
    price       DECIMAL(10,2),
    stock       INT,
    secret_note VARCHAR(200)
);

INSERT INTO products (name, category, price, stock, secret_note) VALUES
 ('Red Mug',        'kitchen',     9.99,  120, 'n/a'),
 ('Blue Mug',       'kitchen',    10.99,   80, 'n/a'),
 ('USB Cable',      'electronics', 4.50,  500, 'n/a'),
 ('HDMI Cable',     'electronics', 7.25,  300, 'n/a'),
 ('Leather Wallet', 'accessories',29.90,   60, 'FLAG{blind_time_based_done}'),
 ('Canvas Belt',    'accessories',19.50,  150, 'n/a');

-- ------------------------------------------------------------
-- Sessions table (Blind SQLi Level 3 - cookie based)
-- Stores a mapping used to resolve a 'track' cookie to user info.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tracking (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    token      VARCHAR(120) NOT NULL,
    username   VARCHAR(120) NOT NULL,
    visits     INT DEFAULT 1
);

INSERT INTO tracking (token, username, visits) VALUES
 ('tk_alice',   'alice',   5),
 ('tk_bob',     'bob',     3),
 ('tk_charlie', 'charlie', 1);

-- ------------------------------------------------------------
-- Lab-wide flags table (for reference / verification)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS flags (
    level_id VARCHAR(40) PRIMARY KEY,
    flag     VARCHAR(200)
);

INSERT INTO flags (level_id, flag) VALUES
 ('sqli2_l1', 'FLAG{2nd_order_password_hijack}'),
 ('sqli2_l2', 'FLAG{2nd_order_stored_comment}'),
 ('sqli2_l3', 'FLAG{2nd_order_admin_reset_success}'),
 ('bsqli_l1', 'FLAG{blind_boolean_admin_pwn}'),
 ('bsqli_l2', 'FLAG{blind_time_based_done}'),
 ('bsqli_l3', 'FLAG{blind_cookie_header_win}'),
 ('domxss_l1','FLAG{dom_xss_hash_sink}'),
 ('domxss_l2','FLAG{dom_xss_filter_bypass}'),
 ('domxss_l3','FLAG{dom_xss_strict_filter_bypass}');
