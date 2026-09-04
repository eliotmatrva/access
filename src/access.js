import crypto from "node:crypto";
import { AccessError, codes } from "./errors.js";
import { assertPermissions, can as canCheck } from "./authz.js";
import { hashPassword, verifyPassword, verifyPasswordDummy } from "./password.js";
import { cookieFromReq, readToken, sessionClearCookie, sessionSetCookie, signToken } from "./session.js";
import { normalizeEmail, publicUser } from "./public-user.js";

const DEFAULT_COOKIE = {
  name: "access_session",
  maxAgeSec: 60 * 60 * 24 * 7,
  path: "/",
  sameSite: "Lax",
};

function hashInviteToken(token) {
  return crypto.createHash("sha256").update(token).digest("base64url");
}

function requireSecret(secret, production) {
  if (!secret || typeof secret !== "string") {
    throw new AccessError(codes.MISSING_SECRET, "SESSION_SECRET is required", 500);
  }
  if (production && (secret === "dev" || secret.length < 16)) {
    throw new AccessError(
      codes.MISSING_SECRET,
      "Production requires a SESSION_SECRET of at least 16 characters (not \"dev\")",
      500,
    );
  }
}

function stamp(pwc) {
  if (!pwc) return 0;
  const n = pwc instanceof Date ? pwc.getTime() : new Date(pwc).getTime();
  return Number.isFinite(n) ? n : 0;
}

export function createAccess(opts = {}) {
  if (!opts.store) throw new AccessError(codes.INVALID, "store is required");
  const catalog = Object.freeze([...(opts.permissions || [])]);
  const production = opts.production ?? process.env.NODE_ENV === "production";
  requireSecret(opts.secret, production);
  const secret = opts.secret;
  const store = opts.store;
  const cookie = {
    ...DEFAULT_COOKIE,
    ...(opts.cookie || {}),
    secure: opts.cookie?.secure ?? production,
  };
  const now = opts.now || (() => new Date());
  const onEvent = typeof opts.onEvent === "function" ? opts.onEvent : () => {};

  function emit(name, payload) {
    try {
      onEvent(name, payload);
    } catch {
      /* host logger must not break auth */
    }
  }

  async function ready() {
    if (typeof store.ready === "function") await store.ready();
    const boot = opts.bootstrap;
    if (!boot?.email || !boot?.password) return { bootstrapped: false };
    const existing = await store.listUsers();
    if (existing.length) return { bootstrapped: false };
    const perms = boot.permissions?.length ? boot.permissions : [...catalog];
    await users.create({
      name: boot.name || "Owner",
      email: boot.email,
      password: boot.password,
      permissions: perms,
    });
    emit("user.bootstrapped", { email: normalizeEmail(boot.email) });
    return { bootstrapped: true };
  }

  const users = {
    async list() {
      return (await store.listUsers()).map(publicUser);
    },
    async get(id) {
      return publicUser(await store.getUser(id));
    },
    async create({ name, email, permissions = [], password, status = "active" }) {
      assertPermissions(catalog, permissions);
      const row = await store.createUser({ name, email, permissions, status });
      if (password) await store.putCredential(row.id, await hashPassword(password));
      emit("user.created", { id: row.id, email: row.email });
      return publicUser(await store.getUser(row.id));
    },
    async update(id, patch) {
      if (patch.permissions) assertPermissions(catalog, patch.permissions);
      return publicUser(await store.updateUser(id, patch));
    },
    async disable(id) {
      const row = await store.disableUser(id);
      emit("user.disabled", { id });
      return publicUser(row);
    },
    async setPermissions(id, permissions) {
      assertPermissions(catalog, permissions);
      const row = await store.updateUser(id, { permissions });
      emit("user.permissions", { id, permissions });
      return publicUser(row);
    },
  };

  const invites = {
    async create({ email, permissions = [], ttlSec = 60 * 60 * 24 * 7, createdBy = null }) {
      assertPermissions(catalog, permissions);
      const norm = normalizeEmail(email);
      if (!norm) throw new AccessError(codes.INVALID, "email is required");
      const token = crypto.randomBytes(24).toString("base64url");
      const row = {
        id: crypto.randomUUID(),
        email: norm,
        permissions: [...permissions],
        tokenHash: hashInviteToken(token),
        createdBy,
        expiresAt: new Date(now().getTime() + ttlSec * 1000),
        consumedAt: null,
      };
      await store.putInvite(row);
      emit("invite.created", { id: row.id, email: norm });
      return { id: row.id, email: norm, permissions: [...permissions], expiresAt: row.expiresAt, token };
    },
    async consume(token, { name, password }) {
      if (!token) throw new AccessError(codes.INVALID, "Invite token is required");
      const row = await store.getInviteByTokenHash(hashInviteToken(token));
      if (!row) throw new AccessError(codes.NOT_FOUND, "Invite not found", 404);
      if (row.consumedAt) throw new AccessError(codes.EXPIRED, "Invite already used");
      if (new Date(row.expiresAt).getTime() <= now().getTime()) {
        throw new AccessError(codes.EXPIRED, "Invite expired");
      }
      const user = await users.create({
        name: name || row.email,
        email: row.email,
        permissions: row.permissions,
        password,
      });
      await store.consumeInvite(row.id, now());
      emit("invite.consumed", { id: row.id, userId: user.id });
      return user;
    },
  };

  async function authenticate(email, password) {
    const norm = normalizeEmail(email);
    const row = norm ? await store.getUserByEmail(norm) : null;
    const cred = row ? await store.getCredential(row.id) : null;
    if (!row || !cred) {
      await verifyPasswordDummy(password);
      emit("login.fail", { email: norm || "" });
      throw new AccessError(codes.BAD_CREDENTIALS, "Invalid email or password", 401);
    }
    const ok = await verifyPassword(password, cred.passwordHash);
    if (!ok) {
      emit("login.fail", { email: norm });
      throw new AccessError(codes.BAD_CREDENTIALS, "Invalid email or password", 401);
    }
    if (row.status === "disabled") {
      emit("login.fail", { email: norm, reason: "disabled" });
      throw new AccessError(codes.DISABLED, "Account is disabled", 403);
    }
    emit("login.ok", { id: row.id, email: row.email });
    return publicUser(row);
  }

  function issueToken(user, full) {
    return signToken({ u: user.id, t: now().getTime(), pwc: stamp(full?.passwordChangedAt) }, secret);
  }

  async function authenticateToken(token) {
    const payload = readToken(token, secret);
    if (!payload?.u || !payload.t) return null;
    if (now().getTime() - Number(payload.t) > cookie.maxAgeSec * 1000) return null;
    const full = await store.getUser(payload.u);
    if (!full || full.status === "disabled") return null;
    if (stamp(full.passwordChangedAt) !== Number(payload.pwc || 0)) return null;
    return publicUser(full);
  }

  async function changePassword(userId, currentPassword, newPassword) {
    const cred = await store.getCredential(userId);
    if (!cred || !(await verifyPassword(currentPassword, cred.passwordHash))) {
      throw new AccessError(codes.BAD_CREDENTIALS, "Current password is wrong", 401);
    }
    await store.putCredential(userId, await hashPassword(newPassword));
    emit("password.changed", { id: userId });
    return users.get(userId);
  }

  function can(user, permission) {
    if (permission && !catalog.includes(permission)) {
      throw new AccessError(codes.UNKNOWN_PERMISSION, `Unknown permission: ${permission}`);
    }
    return canCheck(user, permission);
  }

  function setCookieHeader(res, token) {
    res.setHeader("Set-Cookie", sessionSetCookie(cookie.name, token, cookie));
  }

  function clearCookieHeader(res) {
    res.setHeader("Set-Cookie", sessionClearCookie(cookie.name, cookie));
  }

  function requireAuth() {
    return async (req, res, next) => {
      try {
        const user = await authenticateToken(cookieFromReq(req, cookie.name));
        if (!user) {
          return res.status(401).json({ error: "Sign in required", code: codes.UNAUTHENTICATED });
        }
        req.accessUser = user;
        next();
      } catch (err) {
        next(err);
      }
    };
  }

  function require(permission) {
    assertPermissions(catalog, [permission]);
    const auth = requireAuth();
    return async (req, res, next) => {
      await auth(req, res, (err) => {
        if (err) return next(err);
        if (res.headersSent) return;
        if (!canCheck(req.accessUser, permission)) {
          return res.status(403).json({ error: "Forbidden", code: codes.FORBIDDEN });
        }
        next();
      });
    };
  }

  return {
    ready,
    permissions: catalog,
    cookie,
    store,
    users,
    invites,
    authenticate,
    authenticateToken,
    issueToken,
    changePassword,
    can,
    requireAuth,
    require,
    cookieFromReq: (req) => cookieFromReq(req, cookie.name),
    setCookieHeader,
    clearCookieHeader,
    emit,
  };
}

export { AccessError, codes } from "./errors.js";
export { MemoryStore } from "./stores/memory.js";
export { can } from "./authz.js";
