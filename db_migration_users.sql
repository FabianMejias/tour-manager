-- Tour Manager: migración de permisos (aditiva; no elimina/modifica tablas operativas)
CREATE TABLE IF NOT EXISTS user_permissions (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission VARCHAR(100) NOT NULL,
    allowed BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, permission)
);

CREATE TABLE IF NOT EXISTS permission_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS profile_permissions (
    profile_id UUID NOT NULL REFERENCES permission_profiles(id) ON DELETE CASCADE,
    permission VARCHAR(100) NOT NULL,
    allowed BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY(profile_id, permission)
);

CREATE TABLE IF NOT EXISTS user_profiles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    profile_id UUID NOT NULL REFERENCES permission_profiles(id) ON DELETE CASCADE,
    PRIMARY KEY(user_id, profile_id)
);

CREATE TABLE IF NOT EXISTS user_permission_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    changed_by UUID REFERENCES users(id),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    permission VARCHAR(100) NOT NULL,
    old_allowed BOOLEAN,
    new_allowed BOOLEAN,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
