import crypto from "node:crypto";
import { AccessError, codes } from "./errors.js";
import { hashPassword, verifyPassword, verifyPasswordDummy } from "./password.js";
import { signToken, readToken } from "./session.js";
import { assertPermissions, can } from "./authz.js";
import { publicUser, normalizeEmail } from "./public-user.js";
import { MemoryStore } from "./stores/memory.js";

export { AccessError, codes, can, MemoryStore };

const DEFAULT_SESSION_TTL_SEC = 60 * 60 * 24 * 14; // 14 days
const DEFAULT_INVITE_TTL_SEC = 60 * 60 * 24 * 7; // 7 days

function requireSecret(secret) {
  if (!secret || typeof secret !== "string" || secret.length < 16) {
    throw new AccessError(
      codes.MISSING_SECRET,
      "secret must be a string of at least 16 characters",
      500,
    );
  }
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

/**
 * @param {{
 *   store: object,
 *   secret: string,
 *   permissions?: string[],
 *   sessionTtlSec?: number,
 *   inviteTtlSec?: number,
 *   cookieName?: string,
 * }} options
 */
export function createAccess(options = {}) {
  const store = options.store;
  if (!store) throw new AccessError(codes.INVALID, "store is required");
  const secret = options.secret;
  requireSecret(secret);
  const permissions = Array.isArray(options.permissions) ? [...options.permissions] : [];
  const sessionTtlSec = Number(options.sessionTtlSec) || DEFAULT_SESSION_TTL_SEC;
  const inviteTtlSec = Number(options.inviteTtlSec) || DEFAULT_INVITE_TTL_SEC;
  const cookieName = options.cookieName || "access_session";

  async function ready() {
    if (typeof store.ready === "function") await store.ready();
  }

  async function bootstrapAdmin({ name, email, password, permissions: perms = ["admin"] } = {}) {
    await ready();
    const existing = await store.listUsers();
    if (existing.length > 0) {
      return { created: false, user: null };
    }
    assertPermissions(permissions.length ? permissions : perms, perms);
    const user = await store.createUser({
      name,
      email,
      permissions: perms,
      status: "active",
    });
    const passwordHash = await hashPassword(password);
    await store.putCredential(user.id, passwordHash);
    return { created: true, user: publicUser(user) };
  }

  async function register({ name, email, password, permissions: perms = [] } = {}) {
    await ready();
    assertPermissions(permissions, perms);
    const user = await store.createUser({
      name,
      email,
      permissions: perms,
      status: "active",
    });
    const passwordHash = await hashPassword(password);
    await store.putCredential(user.id, passwordHash);
    return publicUser(user);
  }

  async function login(email, password) {
    await ready();
    const norm = normalizeEmail(email);
    const user = await store.getUserByEmail(norm);
    if (!user) {
      await verifyPasswordDummy(password);
      throw new AccessError(codes.BAD_CREDENTIALS, "Invalid email or password", 401);
    }
    if (user.status === "disabled") {
      throw new AccessError(codes.DISABLED, "Account is disabled", 403);
    }
    const cred = await store.getCredential(user.id);
    if (!cred?.passwordHash) {
      await verifyPasswordDummy(password);
      throw new AccessError(codes.BAD_CREDENTIALS, "Invalid email or password", 401);
    }
    const ok = await verifyPassword(password, cred.passwordHash);
    if (!ok) {
      throw new AccessError(codes.BAD_CREDENTIALS, "Invalid email or password", 401);
    }
    const sessionId = crypto.randomUUID();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + sessionTtlSec * 1000);
    await store.putSession({
      id: sessionId,
      userId: user.id,
      issuedAt: now,
      expiresAt,
      revokedAt: null,
    });
    const token = signToken(
      {
        sid: sessionId,
        sub: user.id,
        exp: Math.floor(expiresAt.getTime() / 1000),
      },
      secret,
    );
    return {
      user: publicUser(user),
      token,
      expiresAt,
      cookieName,
      sessionTtlSec,
    };
  }

  async function logout(token) {
    await ready();
    const payload = readToken(token, secret);
    if (!payload?.sid) return { ok: true };
    await store.revokeSession(payload.sid);
    return { ok: true };
  }

  async function userFromToken(token) {
    await ready();
    const payload = readToken(token, secret);
    if (!payload?.sid || !payload?.sub) {
      throw new AccessError(codes.UNAUTHENTICATED, "Not authenticated", 401);
    }
    if (payload.exp && payload.exp * 1000 < Date.now()) {
      throw new AccessError(codes.EXPIRED, "Session expired", 401);
    }
    const session = await store.getSession(payload.sid);
    if (!session || session.revokedAt) {
      throw new AccessError(codes.UNAUTHENTICATED, "Not authenticated", 401);
    }
    if (session.expiresAt && new Date(session.expiresAt).getTime() < Date.now()) {
      throw new AccessError(codes.EXPIRED, "Session expired", 401);
    }
    if (session.userId !== payload.sub) {
      throw new AccessError(codes.UNAUTHENTICATED, "Not authenticated", 401);
    }
    const user = await store.getUser(payload.sub);
    if (!user) {
      throw new AccessError(codes.UNAUTHENTICATED, "Not authenticated", 401);
    }
    if (user.status === "disabled") {
      throw new AccessError(codes.DISABLED, "Account is disabled", 403);
    }
    return publicUser(user);
  }

  async function changePassword(userId, currentPassword, newPassword) {
    await ready();
    const user = await store.getUser(userId);
    if (!user) throw new AccessError(codes.NOT_FOUND, "User not found", 404);
    const cred = await store.getCredential(userId);
    if (!cred?.passwordHash) {
      throw new AccessError(codes.BAD_CREDENTIALS, "Invalid password", 401);
    }
    const ok = await verifyPassword(currentPassword, cred.passwordHash);
    if (!ok) {
      throw new AccessError(codes.BAD_CREDENTIALS, "Invalid password", 401);
    }
    const passwordHash = await hashPassword(newPassword);
    await store.putCredential(userId, passwordHash);
    return { ok: true };
  }

  async function listUsers(actor) {
    await ready();
    if (!actor || !can(actor, "admin")) {
      throw new AccessError(codes.FORBIDDEN, "Admin required", 403);
    }
    const rows = await store.listUsers();
    return rows.map(publicUser);
  }

  async function createUser(actor, { name, email, permissions: perms = [], password } = {}) {
    await ready();
    if (!actor || !can(actor, "admin")) {
      throw new AccessError(codes.FORBIDDEN, "Admin required", 403);
    }
    assertPermissions(permissions, perms);
    const user = await store.createUser({
      name,
      email,
      permissions: perms,
      status: "active",
    });
    if (password) {
      const passwordHash = await hashPassword(password);
      await store.putCredential(user.id, passwordHash);
    }
    return publicUser(user);
  }

  async function updateUser(actor, userId, patch) {
    await ready();
    if (!actor || !can(actor, "admin")) {
      throw new AccessError(codes.FORBIDDEN, "Admin required", 403);
    }
    if (patch.permissions) assertPermissions(permissions, patch.permissions);
    const user = await store.updateUser(userId, patch);
    return publicUser(user);
  }

  async function disableUser(actor, userId) {
    await ready();
    if (!actor || !can(actor, "admin")) {
      throw new AccessError(codes.FORBIDDEN, "Admin required", 403);
    }
    const user = await store.disableUser(userId);
    return publicUser(user);
  }

  async function createInvite(actor, { email, permissions: perms = [] } = {}) {
    await ready();
    if (!actor || !can(actor, "admin")) {
      throw new AccessError(codes.FORBIDDEN, "Admin required", 403);
    }
    assertPermissions(permissions, perms);
    const token = crypto.randomBytes(32).toString("base64url");
    const tokenHash = hashToken(token);
    const now = new Date();
    const expiresAt = new Date(now.getTime() + inviteTtlSec * 1000);
    const row = {
      id: crypto.randomUUID(),
      email: normalizeEmail(email),
      permissions: perms,
      tokenHash,
      createdBy: actor.id,
      expiresAt,
      consumedAt: null,
    };
    await store.putInvite(row);
    return { token, invite: { id: row.id, email: row.email, permissions: row.permissions, expiresAt } };
  }

  async function acceptInvite(token, { name, password } = {}) {
    await ready();
    if (!token) throw new AccessError(codes.INVALID, "token is required");
    const tokenHash = hashToken(token);
    const invite = await store.getInviteByTokenHash(tokenHash);
    if (!invite) throw new AccessError(codes.NOT_FOUND, "Invite not found", 404);
    if (invite.consumedAt) throw new AccessError(codes.EXPIRED, "Invite already used", 410);
    if (new Date(invite.expiresAt).getTime() < Date.now()) {
      throw new AccessError(codes.EXPIRED, "Invite expired", 410);
    }
    assertPermissions(permissions, invite.permissions);
    const user = await store.createUser({
      name: name || invite.email,
      email: invite.email,
      permissions: invite.permissions,
      status: "active",
    });
    if (password) {
      const passwordHash = await hashPassword(password);
      await store.putCredential(user.id, passwordHash);
    }
    await store.consumeInvite(invite.id);
    return publicUser(user);
  }

  function authenticate(token) {
    return userFromToken(token);
  }

  function require(permission) {
    return async (token) => {
      const user = await userFromToken(token);
      if (!can(user, permission)) {
        throw new AccessError(codes.FORBIDDEN, `Missing permission: ${permission}`, 403);
      }
      return user;
    };
  }

  return {
    ready,
    bootstrapAdmin,
    register,
    login,
    logout,
    userFromToken,
    authenticate,
    require,
    changePassword,
    listUsers,
    createUser,
    updateUser,
    disableUser,
    createInvite,
    acceptInvite,
    can,
    permissions,
    cookieName,
    sessionTtlSec,
    store,
  };
}
