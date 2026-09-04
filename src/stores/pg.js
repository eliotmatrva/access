import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { AccessError, codes } from "../errors.js";
import { normalizeEmail } from "../public-user.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function mapUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    status: row.status,
    permissions: Array.isArray(row.permissions) ? row.permissions : JSON.parse(row.permissions || "[]"),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    passwordChangedAt: row.password_changed_at,
  };
}

export class PostgresStore {
  /** @param {import("pg").Pool | import("pg").Client} pool */
  constructor(pool) {
    if (!pool) throw new AccessError(codes.INVALID, "pool is required");
    this.pool = pool;
  }

  async ready() {
    // no-op; caller may call migrate()
  }

  async migrate() {
    const schemaPath = path.join(__dirname, "../../sql/schema.sql");
    const sql = fs.readFileSync(schemaPath, "utf8");
    await this.pool.query(sql);
  }

  async listUsers() {
    const { rows } = await this.pool.query(
      `SELECT id, name, email, status, permissions, created_at, updated_at, password_changed_at
       FROM access_user ORDER BY created_at ASC`,
    );
    return rows.map(mapUser);
  }

  async getUser(id) {
    const { rows } = await this.pool.query(
      `SELECT id, name, email, status, permissions, created_at, updated_at, password_changed_at
       FROM access_user WHERE id = $1`,
      [id],
    );
    return mapUser(rows[0]);
  }

  async getUserByEmail(email) {
    const norm = normalizeEmail(email);
    const { rows } = await this.pool.query(
      `SELECT id, name, email, status, permissions, created_at, updated_at, password_changed_at
       FROM access_user WHERE email = $1`,
      [norm],
    );
    return mapUser(rows[0]);
  }

  async createUser({ name, email, permissions, status = "active", passwordChangedAt = null }) {
    const norm = normalizeEmail(email);
    if (!norm) throw new AccessError(codes.INVALID, "email is required");
    const id = crypto.randomUUID();
    const now = new Date();
    const perms = [...(permissions || [])];
    const st = status === "disabled" ? "disabled" : "active";
    try {
      const { rows } = await this.pool.query(
        `INSERT INTO access_user (id, name, email, status, permissions, created_at, updated_at, password_changed_at)
         VALUES ($1, $2, $3, $4, $5::jsonb, $6, $6, $7)
         RETURNING id, name, email, status, permissions, created_at, updated_at, password_changed_at`,
        [id, String(name || "").trim() || norm, norm, st, JSON.stringify(perms), now, passwordChangedAt],
      );
      return mapUser(rows[0]);
    } catch (err) {
      if (err && err.code === "23505") {
        throw new AccessError(codes.EMAIL_TAKEN, "Email already in use");
      }
      throw err;
    }
  }

  async updateUser(id, patch) {
    const current = await this.getUser(id);
    if (!current) throw new AccessError(codes.NOT_FOUND, "User not found", 404);
    const name = patch.name != null ? String(patch.name).trim() || current.name : current.name;
    const status =
      patch.status === "active" || patch.status === "disabled" ? patch.status : current.status;
    const permissions = patch.permissions ? [...patch.permissions] : current.permissions;
    const passwordChangedAt =
      patch.passwordChangedAt != null ? new Date(patch.passwordChangedAt) : current.passwordChangedAt;
    const now = new Date();
    const { rows } = await this.pool.query(
      `UPDATE access_user
       SET name = $2, status = $3, permissions = $4::jsonb, updated_at = $5, password_changed_at = $6
       WHERE id = $1
       RETURNING id, name, email, status, permissions, created_at, updated_at, password_changed_at`,
      [id, name, status, JSON.stringify(permissions), now, passwordChangedAt],
    );
    return mapUser(rows[0]);
  }

  async disableUser(id) {
    return this.updateUser(id, { status: "disabled" });
  }

  async getCredential(userId) {
    const { rows } = await this.pool.query(
      `SELECT user_id, password_hash, changed_at FROM access_credential WHERE user_id = $1`,
      [userId],
    );
    if (!rows[0]) return null;
    return {
      userId: rows[0].user_id,
      passwordHash: rows[0].password_hash,
      changedAt: rows[0].changed_at,
    };
  }

  async putCredential(userId, passwordHash) {
    const changedAt = new Date();
    await this.pool.query(
      `INSERT INTO access_credential (user_id, password_hash, changed_at)
       VALUES ($1, $2, $3)
       ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash, changed_at = EXCLUDED.changed_at`,
      [userId, passwordHash, changedAt],
    );
    await this.pool.query(
      `UPDATE access_user SET password_changed_at = $2, updated_at = $2 WHERE id = $1`,
      [userId, changedAt],
    );
    return { userId, changedAt };
  }

  async putInvite(row) {
    await this.pool.query(
      `INSERT INTO access_invite (id, email, permissions, token_hash, created_by, expires_at, consumed_at)
       VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7)`,
      [
        row.id,
        row.email,
        JSON.stringify(row.permissions || []),
        row.tokenHash,
        row.createdBy || null,
        row.expiresAt,
        row.consumedAt || null,
      ],
    );
    return { ...row, permissions: [...(row.permissions || [])] };
  }

  async getInviteByTokenHash(tokenHash) {
    const { rows } = await this.pool.query(
      `SELECT id, email, permissions, token_hash, created_by, expires_at, consumed_at
       FROM access_invite WHERE token_hash = $1`,
      [tokenHash],
    );
    if (!rows[0]) return null;
    const r = rows[0];
    return {
      id: r.id,
      email: r.email,
      permissions: Array.isArray(r.permissions) ? r.permissions : JSON.parse(r.permissions || "[]"),
      tokenHash: r.token_hash,
      createdBy: r.created_by,
      expiresAt: r.expires_at,
      consumedAt: r.consumed_at,
    };
  }

  async consumeInvite(id, at = new Date()) {
    const { rows } = await this.pool.query(
      `UPDATE access_invite SET consumed_at = $2 WHERE id = $1
       RETURNING id, email, permissions, token_hash, created_by, expires_at, consumed_at`,
      [id, at],
    );
    if (!rows[0]) throw new AccessError(codes.NOT_FOUND, "Invite not found", 404);
    const r = rows[0];
    return {
      id: r.id,
      email: r.email,
      permissions: Array.isArray(r.permissions) ? r.permissions : JSON.parse(r.permissions || "[]"),
      tokenHash: r.token_hash,
      createdBy: r.created_by,
      expiresAt: r.expires_at,
      consumedAt: r.consumed_at,
    };
  }

  async putSession(row) {
    await this.pool.query(
      `INSERT INTO access_session (id, user_id, issued_at, expires_at, revoked_at)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (id) DO UPDATE SET revoked_at = EXCLUDED.revoked_at`,
      [row.id, row.userId, row.issuedAt || new Date(), row.expiresAt, row.revokedAt || null],
    );
    return { ...row };
  }

  async getSession(id) {
    const { rows } = await this.pool.query(
      `SELECT id, user_id, issued_at, expires_at, revoked_at FROM access_session WHERE id = $1`,
      [id],
    );
    if (!rows[0]) return null;
    const r = rows[0];
    return {
      id: r.id,
      userId: r.user_id,
      issuedAt: r.issued_at,
      expiresAt: r.expires_at,
      revokedAt: r.revoked_at,
    };
  }

  async revokeSession(id, at = new Date()) {
    const { rows } = await this.pool.query(
      `UPDATE access_session SET revoked_at = $2 WHERE id = $1
       RETURNING id, user_id, issued_at, expires_at, revoked_at`,
      [id, at],
    );
    if (!rows[0]) return null;
    const r = rows[0];
    return {
      id: r.id,
      userId: r.user_id,
      issuedAt: r.issued_at,
      expiresAt: r.expires_at,
      revokedAt: r.revoked_at,
    };
  }
}
