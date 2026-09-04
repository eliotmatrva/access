import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createAccess, MemoryStore, AccessError, codes, can } from "../src/access.js";

const SECRET = "test-secret-at-least-16-chars";

function makeAccess(perms = ["admin", "edit", "view"]) {
  return createAccess({
    store: new MemoryStore(),
    secret: SECRET,
    permissions: perms,
  });
}

describe("createAccess", () => {
  it("requires store and secret", () => {
    assert.throws(() => createAccess({ secret: SECRET }), /store/);
    assert.throws(() => createAccess({ store: new MemoryStore() }), /secret/);
  });

  it("bootstraps first admin only when empty", async () => {
    const access = makeAccess();
    const first = await access.bootstrapAdmin({
      name: "Ada",
      email: "ada@example.com",
      password: "password1",
      permissions: ["admin"],
    });
    assert.equal(first.created, true);
    assert.equal(first.user.email, "ada@example.com");
    assert.ok(can(first.user, "admin"));

    const second = await access.bootstrapAdmin({
      name: "Bob",
      email: "bob@example.com",
      password: "password1",
      permissions: ["admin"],
    });
    assert.equal(second.created, false);
  });

  it("logs in and authenticates", async () => {
    const access = makeAccess();
    await access.bootstrapAdmin({
      name: "Ada",
      email: "ada@example.com",
      password: "password1",
      permissions: ["admin"],
    });
    const { user, token } = await access.login("ada@example.com", "password1");
    assert.equal(user.email, "ada@example.com");
    const me = await access.authenticate(token);
    assert.equal(me.id, user.id);
  });

  it("rejects bad credentials", async () => {
    const access = makeAccess();
    await access.bootstrapAdmin({
      name: "Ada",
      email: "ada@example.com",
      password: "password1",
      permissions: ["admin"],
    });
    await assert.rejects(
      () => access.login("ada@example.com", "wrong"),
      (err) => err instanceof AccessError && err.code === codes.BAD_CREDENTIALS,
    );
  });

  it("logs out and invalidates token", async () => {
    const access = makeAccess();
    await access.bootstrapAdmin({
      name: "Ada",
      email: "ada@example.com",
      password: "password1",
      permissions: ["admin"],
    });
    const { token } = await access.login("ada@example.com", "password1");
    await access.logout(token);
    await assert.rejects(
      () => access.authenticate(token),
      (err) => err instanceof AccessError && err.code === codes.UNAUTHENTICATED,
    );
  });

  it("changes password", async () => {
    const access = makeAccess();
    const { user } = await access.bootstrapAdmin({
      name: "Ada",
      email: "ada@example.com",
      password: "password1",
      permissions: ["admin"],
    });
    await access.changePassword(user.id, "password1", "password2");
    await assert.rejects(() => access.login("ada@example.com", "password1"));
    const { token } = await access.login("ada@example.com", "password2");
    assert.ok(token);
  });

  it("admin can list and create users", async () => {
    const access = makeAccess();
    const { user: admin } = await access.bootstrapAdmin({
      name: "Ada",
      email: "ada@example.com",
      password: "password1",
      permissions: ["admin"],
    });
    const created = await access.createUser(admin, {
      name: "Bob",
      email: "bob@example.com",
      permissions: ["view"],
      password: "password1",
    });
    assert.equal(created.email, "bob@example.com");
    const users = await access.listUsers(admin);
    assert.equal(users.length, 2);
  });

  it("invite flow", async () => {
    const access = makeAccess();
    const { user: admin } = await access.bootstrapAdmin({
      name: "Ada",
      email: "ada@example.com",
      password: "password1",
      permissions: ["admin"],
    });
    const { token } = await access.createInvite(admin, {
      email: "carol@example.com",
      permissions: ["edit"],
    });
    const user = await access.acceptInvite(token, {
      name: "Carol",
      password: "password1",
    });
    assert.equal(user.email, "carol@example.com");
    assert.ok(can(user, "edit"));
  });

  it("require checks permission", async () => {
    const access = makeAccess();
    await access.bootstrapAdmin({
      name: "Ada",
      email: "ada@example.com",
      password: "password1",
      permissions: ["admin"],
    });
    const { token } = await access.login("ada@example.com", "password1");
    const user = await access.require("admin")(token);
    assert.ok(user);
    await assert.rejects(
      () => access.require("edit")(token),
      (err) => err.code === codes.FORBIDDEN,
    );
  });
});
