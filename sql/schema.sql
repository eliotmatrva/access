-- @eliotmatrva/access
CREATE TABLE IF NOT EXISTS access_user (
  id uuid PRIMARY KEY,
  name text NOT NULL,
  email text NOT NULL UNIQUE,
  status text NOT NULL,
  permissions jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  password_changed_at timestamptz
);
CREATE TABLE IF NOT EXISTS access_credential (
  user_id uuid PRIMARY KEY REFERENCES access_user (id) ON DELETE CASCADE,
  password_hash text NOT NULL,
  changed_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS access_session (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES access_user (id) ON DELETE CASCADE,
  issued_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);
CREATE TABLE IF NOT EXISTS access_invite (
  id uuid PRIMARY KEY,
  email text NOT NULL,
  permissions jsonb NOT NULL DEFAULT '[]'::jsonb,
  token_hash text NOT NULL UNIQUE,
  created_by uuid,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz
);
