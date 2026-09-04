import crypto from "node:crypto";
import { AccessError, codes } from "../errors.js";
import { normalizeEmail } from "../public-user.js";

function cloneUser(row) {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    status: row.status,
    permissions: [...row.permissions],
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    passwordChangedAt: row.passwordChangedAt,
  };
}

export class MemoryStore {
  constructor() {
    this.users = new Map();
    this.emails = new Map();
    this.credentials = new Map();
    this.invites = new Map();
    this.inviteTokens = new Map();
    this.sessions = new Map();
  }

  async ready() {}

  async listUsers() {
    return [...this.users.values()].map(cloneUser);
  }

  async getUser(id) {
    const row = this.users.get(id);
    return row ? cloneUser(row) : null;
  }

  async getUserByEmail(email) {
    const id = this.emails.get(normalizeEmail(email));
    return id ? this.getUser(id) : null;
  }

  async createUser({ name, email, permissions, status = "active", passwordChangedAt = null }) {
    const norm = normalizeEmail(email);
    if (!norm) throw new AccessError(codes.INVALID, "email is required");
    if (this.emails.has(norm)) throw new AccessError(codes.EMAIL_TAKEN, "Email already in use");
    const now = new Date();
    const row = {
      id: crypto.randomUUID(),
      name: String(name || "").trim() || norm,
      email: norm,
      status: status === "disabled" ? "disabled" : "active",
      permissions: [...(permissions || [])],
      createdAt: now,
      updatedAt: now,
      passwordChangedAt: passwordChangedAt ? new Date(passwordChangedAt) : null,
    };
    this.users.set(row.id, row);
    this.emails.set(norm, row.id);
    return cloneUser(row);
  }

  async updateUser(id, patch) {
    const row = this.users.get(id);
    if (!row) throw new AccessError(codes.NOT_FOUND, "User not found", 404);
    if (patch.name != null) row.name = String(patch.name).trim() || row.name;
    if (patch.status === "active" || patch.status === "disabled") row.status = patch.status;
    if (patch.permissions) row.permissions = [...patch.permissions];
    if (patch.passwordChangedAt != null) row.passwordChangedAt = new Date(patch.passwordChangedAt);
    row.updatedAt = new Date();
    return cloneUser(row);
  }

  async disableUser(id) {
    return this.updateUser(id, { status: "disabled" });
  }

  async getCredential(userId) {
    const row = this.credentials.get(userId);
    return row ? { userId, passwordHash: row.passwordHash, changedAt: row.changedAt } : null;
  }

  async putCredential(userId, passwordHash) {
    const changedAt = new Date();
    this.credentials.set(userId, { passwordHash, changedAt });
    const user = this.users.get(userId);
    if (user) {
      user.passwordChangedAt = changedAt;
      user.updatedAt = changedAt;
    }
    return { userId, changedAt };
  }

  async putInvite(row) {
    this.invites.set(row.id, { ...row, permissions: [...row.permissions] });
    this.inviteTokens.set(row.tokenHash, row.id);
    return { ...row, permissions: [...row.permissions] };
  }

  async getInviteByTokenHash(tokenHash) {
    const id = this.inviteTokens.get(tokenHash);
    if (!id) return null;
    const row = this.invites.get(id);
    return row ? { ...row, permissions: [...row.permissions] } : null;
  }

  async consumeInvite(id, at = new Date()) {
    const row = this.invites.get(id);
    if (!row) throw new AccessError(codes.NOT_FOUND, "Invite not found", 404);
    row.consumedAt = at;
    return { ...row, permissions: [...row.permissions] };
  }

  async putSession(row) {
    this.sessions.set(row.id, { ...row });
    return { ...row };
  }

  async getSession(id) {
    const row = this.sessions.get(id);
    return row ? { ...row } : null;
  }

  async revokeSession(id, at = new Date()) {
    const row = this.sessions.get(id);
    if (!row) return null;
    row.revokedAt = at;
    return { ...row };
  }
}
