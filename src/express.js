import { AccessError, isAccessError } from "./errors.js";
import { cookieFromReq, sessionSetCookie, sessionClearCookie } from "./session.js";

function sendError(res, err) {
  if (isAccessError(err)) {
    return res.status(err.status || 400).json({ error: err.message, code: err.code });
  }
  console.error(err);
  return res.status(500).json({ error: "Internal server error", code: "INTERNAL" });
}

/**
 * @param {ReturnType<import("./access.js").createAccess>} access
 * @param {{ cookie?: { path?: string, sameSite?: string, secure?: boolean } }} [opts]
 */
export function createAccessRouter(access, opts = {}) {
  const cookieOpts = {
    path: opts.cookie?.path || "/",
    sameSite: opts.cookie?.sameSite || "Lax",
    secure: opts.cookie?.secure ?? false,
    maxAgeSec: access.sessionTtlSec,
  };
  const name = access.cookieName;

  function tokenFromReq(req) {
    const header = req.headers?.authorization;
    if (header && String(header).startsWith("Bearer ")) {
      return String(header).slice(7).trim();
    }
    return cookieFromReq(req, name);
  }

  async function authenticate(req, res, next) {
    try {
      const token = tokenFromReq(req);
      if (!token) {
        req.user = null;
        return next();
      }
      req.user = await access.userFromToken(token);
      req.accessToken = token;
      return next();
    } catch (err) {
      if (isAccessError(err) && (err.code === "UNAUTHENTICATED" || err.code === "EXPIRED" || err.code === "DISABLED")) {
        req.user = null;
        return next();
      }
      return sendError(res, err);
    }
  }

  function requireAuth(req, res, next) {
    if (!req.user) {
      return res.status(401).json({ error: "Not authenticated", code: "UNAUTHENTICATED" });
    }
    return next();
  }

  function require(permission) {
    return (req, res, next) => {
      if (!req.user) {
        return res.status(401).json({ error: "Not authenticated", code: "UNAUTHENTICATED" });
      }
      if (!access.can(req.user, permission)) {
        return res.status(403).json({ error: `Missing permission: ${permission}`, code: "FORBIDDEN" });
      }
      return next();
    };
  }

  function router(express) {
    const r = express.Router();
    r.use(authenticate);

    r.post("/login", async (req, res) => {
      try {
        const email = req.body?.email;
        const password = req.body?.password;
        const result = await access.login(email, password);
        res.setHeader(
          "Set-Cookie",
          sessionSetCookie(name, result.token, {
            ...cookieOpts,
            maxAgeSec: result.sessionTtlSec,
          }),
        );
        return res.json({ user: result.user });
      } catch (err) {
        return sendError(res, err);
      }
    });

    r.post("/logout", async (req, res) => {
      try {
        const token = tokenFromReq(req);
        if (token) await access.logout(token);
        res.setHeader("Set-Cookie", sessionClearCookie(name, cookieOpts));
        return res.json({ ok: true });
      } catch (err) {
        return sendError(res, err);
      }
    });

    r.get("/me", requireAuth, (req, res) => {
      return res.json({ user: req.user });
    });

    r.post("/change-password", requireAuth, async (req, res) => {
      try {
        const currentPassword = req.body?.currentPassword ?? req.body?.current;
        const newPassword = req.body?.newPassword ?? req.body?.password;
        await access.changePassword(req.user.id, currentPassword, newPassword);
        return res.json({ ok: true });
      } catch (err) {
        return sendError(res, err);
      }
    });

    r.get("/users", require("admin"), async (req, res) => {
      try {
        const users = await access.listUsers(req.user);
        return res.json({ users });
      } catch (err) {
        return sendError(res, err);
      }
    });

    r.post("/users", require("admin"), async (req, res) => {
      try {
        const user = await access.createUser(req.user, {
          name: req.body?.name,
          email: req.body?.email,
          permissions: req.body?.permissions,
          password: req.body?.password,
        });
        return res.status(201).json({ user });
      } catch (err) {
        return sendError(res, err);
      }
    });

    r.post("/invites", require("admin"), async (req, res) => {
      try {
        const result = await access.createInvite(req.user, {
          email: req.body?.email,
          permissions: req.body?.permissions,
        });
        return res.status(201).json(result);
      } catch (err) {
        return sendError(res, err);
      }
    });

    r.post("/invites/accept", async (req, res) => {
      try {
        const user = await access.acceptInvite(req.body?.token, {
          name: req.body?.name,
          password: req.body?.password,
        });
        return res.status(201).json({ user });
      } catch (err) {
        return sendError(res, err);
      }
    });

    return r;
  }

  return {
    router,
    authenticate,
    requireAuth,
    require,
  };
}

/** @deprecated Use createAccessRouter */
export function attachAccess(access, opts) {
  return createAccessRouter(access, opts);
}
