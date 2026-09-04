import express from "express";
import { AccessError, codes } from "./errors.js";

function sendError(res, err) {
  const status = err instanceof AccessError ? err.status : 500;
  const code = err instanceof AccessError ? err.code : "ERROR";
  const message = err instanceof AccessError ? err.message : "Server error";
  res.status(status).json({ error: message, code });
}

export function createAccessRouter(access, opts = {}) {
  const router = express.Router();
  const adminPermission = opts.adminPermission || "admin";
  const hasAdmin = access.permissions.includes(adminPermission);

  router.post("/login", async (req, res) => {
    try {
      const user = await access.authenticate(req.body?.email, req.body?.password);
      const full = await access.store.getUser(user.id);
      access.setCookieHeader(res, access.issueToken(user, full));
      res.json({ ok: true, user });
    } catch (err) {
      sendError(res, err);
    }
  });

  router.post("/logout", (_req, res) => {
    access.clearCookieHeader(res);
    res.json({ ok: true });
  });

  router.get("/me", access.requireAuth(), (req, res) => {
    res.json({ user: req.accessUser });
  });

  router.post("/change-password", access.requireAuth(), async (req, res) => {
    try {
      const user = await access.changePassword(
        req.accessUser.id,
        req.body?.currentPassword,
        req.body?.newPassword,
      );
      const full = await access.store.getUser(user.id);
      access.setCookieHeader(res, access.issueToken(user, full));
      res.json({ ok: true, user });
    } catch (err) {
      sendError(res, err);
    }
  });

  if (hasAdmin) {
    router.get("/users", access.require(adminPermission), async (_req, res) => {
      try {
        res.json({ users: await access.users.list() });
      } catch (err) {
        sendError(res, err);
      }
    });

    router.post("/users", access.require(adminPermission), async (req, res) => {
      try {
        const user = await access.users.create({
          name: req.body?.name,
          email: req.body?.email,
          permissions: req.body?.permissions || [],
          password: req.body?.password,
        });
        res.status(201).json({ user });
      } catch (err) {
        sendError(res, err);
      }
    });

    router.post("/users/:id/disable", access.require(adminPermission), async (req, res) => {
      try {
        const user = await access.users.disable(req.params.id);
        res.json({ user });
      } catch (err) {
        sendError(res, err);
      }
    });

    router.post("/users/:id/permissions", access.require(adminPermission), async (req, res) => {
      try {
        const user = await access.users.setPermissions(req.params.id, req.body?.permissions || []);
        res.json({ user });
      } catch (err) {
        sendError(res, err);
      }
    });

    router.post("/invites", access.require(adminPermission), async (req, res) => {
      try {
        const invite = await access.invites.create({
          email: req.body?.email,
          permissions: req.body?.permissions || [],
          ttlSec: req.body?.ttlSec,
          createdBy: req.accessUser.id,
        });
        res.status(201).json({ invite });
      } catch (err) {
        sendError(res, err);
      }
    });
  }

  router.post("/invites/consume", async (req, res) => {
    try {
      const user = await access.invites.consume(req.body?.token, {
        name: req.body?.name,
        password: req.body?.password,
      });
      const full = await access.store.getUser(user.id);
      access.setCookieHeader(res, access.issueToken(user, full));
      res.json({ ok: true, user });
    } catch (err) {
      sendError(res, err);
    }
  });

  return router;
}
