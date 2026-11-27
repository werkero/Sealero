-- Sealero server schema, matching Sealero-System-Design section 3.
-- Postgres / Neon. This file supersedes older versioned schema files, kept in archive/ for comparison only.
-- Change the System Design first, then change this file. Never run against production without Tai's explicit approval.
-- This schema has never been run against production.
-- Changes from schema-v3.6: users.is_admin removed, replaced by roles + user_roles;
-- users.disabled_at kept (added in System Design v1.0); new tables roles, user_roles, audit_logs,
-- rate_limits, user_consents, sync_failure_logs, covering admin, audit, rate limiting, consent and sync health.
-- Changes from schema-v1.4: new table oauth_authorizations, covering AI connector (MCP) OAuth authorizations; other 13 tables unchanged.
-- Changes from schema-v1.6: new table dek_wrappings, covering KEK-wrapped DEK ciphertext stored on server for multi-device recovery; server cannot decrypt it; other 14 tables unchanged.
-- Changes from schema-v1.7: dek_wrappings adds kdf_salt and kdf_params, so other devices can derive the same KEK and trial-decrypt to judge a new master password; salt is not secret.
-- Changes from schema-v1.8: adds updated_at triggers for users, vault_items and devices (trigger, not app code); tables unchanged at 15.
-- Changes from schema-v1.9: auth_codes purpose adds 'delete' for delete-account email codes; tables unchanged at 15, no new table.
-- Changes in v1.24 simplification: remove sync_changes, device_sync_state, idempotency_keys, sync_failure_logs; vault_items adds content_hmac; server tables 18 -> 14; web has no local DB, App sync is full-list pull, push-first.
-- Changes in v1.25: remove vault_items.content_hmac; same-content check moves to client local comparison after 409; server only does version check.
-- Changes in v1.30: vault_items CHECK enforces updated_at and device_id for permanent tombstones; oauth_authorizations.refresh_token_hash becomes NOT NULL (token endpoint always issues refresh).
-- Changes in v1.29: server tables 14 -> 15. New table oauth_auth_codes (OAuth authorization codes, 10 minutes, single use, PKCE S256).
-- vault_items: overview/detail ciphertext and nonce become nullable, updated_at becomes nullable, new column deleted_by_device_id (TEXT, no FK, not the existing device_id),
-- CHECK for three states (active / soft-deleted within 30 days / permanent tombstone after 30 days), vault trigger sets updated_at=NULL for permanent tombstones.
-- dek_wrappings: add UNIQUE(user_id) so one row per user; kdf_params format changes to canonical JSON (see System Design v1.29 section 7.1).
-- oauth_authorizations: add refresh_expires_at; expires_at is the current access-token expiry.
-- Changes in v1.48: server tables 15 -> 16. New table mcp_confirmations (MCP get-one trusted confirmation records, single-use, 5-minute expiry).
-- Changes in v1.48: oauth_auth_codes adds client_name (optional AI client name snapshot, carried into oauth_authorizations so the trusted-confirmation page can show it).
-- Changes in v1.48: seed the three roles rows (admin, user, super_admin) idempotently, so a fresh database has roles without a separate seed step; registration also re-seeds for pre-existing databases with an empty roles table.
-- Changes in v1.48 (RBAC): permissions + role_permissions tables; roles.name CHECK is now a format pattern so custom roles can be created; the 7 permissions are seeded and the admin role is granted all 7.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- users 用户表
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    login_password_hash TEXT NOT NULL,
    email_verified_at TIMESTAMPTZ,
    disabled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- devices 设备表
CREATE TABLE devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_name TEXT NOT NULL,
    device_public_key TEXT,
    device_type TEXT NOT NULL CHECK (device_type IN ('app', 'extension', 'web')),
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_devices_user_id ON devices(user_id);

-- vault_items 保险库条目表
-- id is the database column; the API field for the same value is item_id. There is no item_id column in this table.
-- deleted_by_device_id is TEXT (UUID string), no foreign key: deleting a device must not cascade-delete the tombstone, and the tombstone must not block device deletion.
-- Permanent tombstones keep only id (API item_id), user_id, deleted_at, version and deleted_by_device_id; ciphertext, nonce, domain_hmac and device_id are NULL and updated_at is NULL.
CREATE TABLE vault_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    overview_ciphertext TEXT,
    overview_nonce TEXT,
    detail_ciphertext TEXT,
    detail_nonce TEXT,
    domain_hmac TEXT,
    version BIGINT NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    deleted_by_device_id TEXT,
    CHECK (
        (deleted_at IS NULL AND deleted_by_device_id IS NULL AND overview_ciphertext IS NOT NULL AND overview_nonce IS NOT NULL AND detail_ciphertext IS NOT NULL AND detail_nonce IS NOT NULL AND updated_at IS NOT NULL)
        OR (deleted_at IS NOT NULL AND deleted_by_device_id IS NOT NULL AND overview_ciphertext IS NOT NULL AND overview_nonce IS NOT NULL AND detail_ciphertext IS NOT NULL AND detail_nonce IS NOT NULL AND updated_at IS NOT NULL)
        OR (deleted_at IS NOT NULL AND deleted_by_device_id IS NOT NULL AND overview_ciphertext IS NULL AND overview_nonce IS NULL AND detail_ciphertext IS NULL AND detail_nonce IS NULL AND domain_hmac IS NULL AND updated_at IS NULL AND device_id IS NULL)
    )
);

CREATE INDEX idx_vault_items_user_updated ON vault_items(user_id, updated_at);
CREATE INDEX idx_vault_items_user_deleted ON vault_items(user_id, deleted_at);
CREATE INDEX idx_vault_items_user_domain_hmac ON vault_items(user_id, domain_hmac);

-- refresh_tokens 刷新令牌表
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    absolute_expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoked_reason TEXT CHECK (revoked_reason IN ('rotated', 'device_revoked', 'password_changed', 'logout', 'account_disabled')),
    reuse_alerted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE UNIQUE INDEX idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);

-- auth_codes 验证码表
CREATE TABLE auth_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL,
    code_hash TEXT NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('verify', 'reset', 'delete')),
    expires_at TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- server_settings 服务器设置表
CREATE TABLE server_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- roles 角色表
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE CHECK (name ~ '^[a-z][a-z0-9_]{0,63}$'),
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Default roles (System Design v1.48 §3.1): every deployment needs exactly
-- these three rows. Idempotent: re-running the schema never overwrites or
-- duplicates them, and it never touches user_roles. The id column keeps its
-- gen_random_uuid() default; only name is given here.
INSERT INTO roles (name) VALUES ('admin'), ('user'), ('super_admin')
ON CONFLICT (name) DO NOTHING;

-- user_roles 用户角色关联表
CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    assigned_by UUID REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (user_id, role_id)
);

-- permissions 权限表 (System Design v1.48 §3.1)
CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key TEXT NOT NULL UNIQUE,
    module TEXT NOT NULL,
    description TEXT
);

-- Permission catalog (System Design v1.48 §3.1): 7 rows, idempotent.
INSERT INTO permissions (key, module, description) VALUES
    ('overview:read', 'overview', '看控制台总览与用户趋势'),
    ('users:read', 'users', '看用户列表与详情'),
    ('users:manage', 'users', '停用/启用/删除用户、指定/取消管理员、吊销设备'),
    ('settings:manage', 'settings', '看与改服务器设置'),
    ('audit:read', 'audit', '看审计日志'),
    ('roles:manage', 'roles', '增删改角色、改角色权限、指派/移除角色用户'),
    ('dump:read', 'dump', '下载数据库密文 dump')
ON CONFLICT (key) DO NOTHING;

-- role_permissions 角色权限关联表
CREATE TABLE role_permissions (
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    granted_by UUID REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (role_id, permission_id)
);

-- The admin role gets all 7 permissions (System Design v1.48 §3.1); the user
-- role gets none; super_admin is treated in code as having all permissions
-- and is never granted through this table. Idempotent.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p WHERE r.name = 'admin'
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- audit_logs 审计日志表
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    target_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target_type TEXT,
    metadata TEXT,
    ip_address TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_logs_actor_created ON audit_logs(actor_user_id, created_at);
CREATE INDEX idx_audit_logs_target_created ON audit_logs(target_user_id, created_at);

-- login_logs 登录日志表
CREATE TABLE login_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    device_name TEXT,
    ip_address TEXT,
    user_agent TEXT,
    result TEXT NOT NULL CHECK (result IN ('success', 'failed')),
    failure_code TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_login_logs_user_created ON login_logs(user_id, created_at);
CREATE INDEX idx_login_logs_ip_created ON login_logs(ip_address, created_at);

-- rate_limits 限流记录表
CREATE TABLE rate_limits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope TEXT NOT NULL,
    key TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 1,
    window_start TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    UNIQUE (scope, key, window_start)
);

-- user_consents 用户同意记录表
CREATE TABLE user_consents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    policy_type TEXT NOT NULL CHECK (policy_type IN ('privacy')),
    policy_version TEXT NOT NULL,
    consented_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ip_address TEXT,
    UNIQUE (user_id, policy_type, policy_version)
);

-- oauth_authorizations OAuth 授权记录表
CREATE TABLE oauth_authorizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL,
    client_name TEXT,
    redirect_uri TEXT NOT NULL,
    scopes TEXT NOT NULL,
    access_token_hash TEXT NOT NULL,
    refresh_token_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    refresh_expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_oauth_authorizations_user_id ON oauth_authorizations(user_id);

-- dek_wrappings KEK 包过的 DEK 密文表
CREATE TABLE dek_wrappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    dek_version INTEGER NOT NULL,
    wrapped_dek TEXT NOT NULL,
    nonce TEXT NOT NULL,
    kdf_salt TEXT NOT NULL,
    kdf_params TEXT NOT NULL,
    master_password_version INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(user_id, dek_version),
    UNIQUE(user_id)
);

CREATE INDEX idx_dek_wrappings_user_id ON dek_wrappings(user_id);

-- oauth_auth_codes OAuth 授权码表（MCP OAuth 授权码，10 分钟、一次性、PKCE S256；只存码的 SHA256，不存明文码）
CREATE TABLE oauth_auth_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL,
    client_name TEXT,
    redirect_uri TEXT NOT NULL,
    scopes TEXT NOT NULL,
    code_hash TEXT NOT NULL UNIQUE,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL CHECK (code_challenge_method = 'S256'),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_oauth_auth_codes_user_id ON oauth_auth_codes(user_id);
CREATE INDEX idx_oauth_auth_codes_expires_at ON oauth_auth_codes(expires_at);

-- mcp_confirmations MCP 确认记录表（get_vault_item 可信确认，一次性、5 分钟过期；id 由服务端 randomUUID() 生成后显式插入）
CREATE TABLE mcp_confirmations (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    authorization_id UUID NOT NULL REFERENCES oauth_authorizations(id) ON DELETE CASCADE,
    item_id UUID NOT NULL REFERENCES vault_items(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    approved_at TIMESTAMPTZ,
    denied_at TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX mcp_confirmations_user_created_idx ON mcp_confirmations(user_id, created_at DESC);
CREATE INDEX mcp_confirmations_expires_idx ON mcp_confirmations(expires_at);

-- updated_at 触发器（第 10 条定稿：触发器，不用应用代码显式置）
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Vault trigger: permanent tombstones (deleted and ciphertext cleared) keep updated_at NULL; all other vault updates set updated_at to now().
-- The 30-day timing is enforced by the cleanup job, not by this CHECK/trigger; the CHECK only enforces the three state shapes.
CREATE OR REPLACE FUNCTION set_vault_updated_at() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.deleted_at IS NOT NULL AND NEW.overview_ciphertext IS NULL THEN
        NEW.updated_at := NULL;
    ELSE
        NEW.updated_at := now();
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_vault_items_updated_at BEFORE UPDATE ON vault_items FOR EACH ROW EXECUTE FUNCTION set_vault_updated_at();
CREATE TRIGGER trg_devices_updated_at BEFORE UPDATE ON devices FOR EACH ROW EXECUTE FUNCTION set_updated_at();

