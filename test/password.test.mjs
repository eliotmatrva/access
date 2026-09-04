import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { hashPassword, verifyPassword } from "../src/password.js";
import { AccessError, codes } from "../src/errors.js";

describe("password", () => {
  it("hashes and verifies", async () => {
    const hash = await hashPassword("password1");
    assert.ok(hash.startsWith("scrypt$"));
    assert.equal(await verifyPassword("password1", hash), true);
    assert.equal(await verifyPassword("wrong", hash), false);
  });

  it("rejects short passwords", async () => {
    await assert.rejects(
      () => hashPassword("short"),
      (err) => err instanceof AccessError && err.code === codes.INVALID,
    );
  });
});
