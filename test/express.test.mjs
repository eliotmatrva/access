import { describe, it } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { createAccess, MemoryStore } from "../src/access.js";
import { createAccessRouter } from "../src/express.js";

const SECRET = "test-secret-at-least-16-chars";

async function withServer(handler) {
  const access = createAccess({
    store: new MemoryStore(),
    secret: SECRET,
    permissions: ["admin", "edit", "view"],
  });
  await access.bootstrapAdmin({
    name: "Ada",
    email: "ada@example.com",
    password: "password1",
    permissions: ["admin"],
  });
  const wired = createAccessRouter(access);
  const app = express();
  app.use(express.json());
  app.use("/access", wired.router(express));
  app.get("/secret", wired.requireAuth, (req, res) => res.json({ user: req.user }));

  const server = await new Promise((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  const { port } = server.address();
  const base = `http://127.0.0.1:${port}`;

  try {
    await handler({ base, access });
  } finally {
    await new Promise((r) => server.close(r));
  }
}

describe("createAccessRouter", () => {
  it("login, me, and protected route", async () => {
    await withServer(async ({ base }) => {
      const loginRes = await fetch(`${base}/access/login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: "ada@example.com", password: "password1" }),
      });
      assert.equal(loginRes.status, 200);
      const loginBody = await loginRes.json();
      assert.equal(loginBody.user.email, "ada@example.com");
      const setCookie = loginRes.headers.getSetCookie?.() || [];
      const cookie = setCookie.find((c) => c.startsWith("access_session=")) || "";
      assert.ok(cookie.includes("access_session="));

      const meRes = await fetch(`${base}/access/me`, {
        headers: { cookie: cookie.split(";")[0] },
      });
      assert.equal(meRes.status, 200);
      const meBody = await meRes.json();
      assert.equal(meBody.user.email, "ada@example.com");

      const secretRes = await fetch(`${base}/secret`, {
        headers: { cookie: cookie.split(";")[0] },
      });
      assert.equal(secretRes.status, 200);

      const unauth = await fetch(`${base}/secret`);
      assert.equal(unauth.status, 401);
    });
  });
});
