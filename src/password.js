import crypto from "node:crypto";
import { AccessError, codes } from "./errors.js";

const KEY_LEN = 32;
const DEFAULTS = { N: 4096, r: 8, p: 1 };

function scryptAsync(password, salt, opts) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(
      String(password),
      salt,
      KEY_LEN,
      { N: opts.N, r: opts.r, p: opts.p, maxmem: 64 * 1024 * 1024 },
      (err, key) => {
        if (err) reject(err);
        else resolve(key);
      },
    );
  });
}

function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

export async function hashPassword(password, params = {}) {
  if (!password || typeof password !== "string") {
    throw new AccessError(codes.INVALID, "Password is required");
  }
  if (password.length < 8) {
    throw new AccessError(codes.INVALID, "Password must be at least 8 characters");
  }
  const N = params.N || DEFAULTS.N;
  const r = params.r || DEFAULTS.r;
  const p = params.p || DEFAULTS.p;
  const salt = crypto.randomBytes(16);
  const key = await scryptAsync(password, salt, { N, r, p });
  return `scrypt$${N}$${r}$${p}$${b64url(salt)}$${b64url(key)}`;
}

export async function verifyPassword(password, stored) {
  if (!stored || typeof stored !== "string") return false;
  const parts = stored.split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return false;
  const N = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  const salt = Buffer.from(parts[4], "base64url");
  const expect = Buffer.from(parts[5], "base64url");
  if (!salt.length || !expect.length || !N || !r || !p) return false;
  const actual = await scryptAsync(String(password || ""), salt, { N, r, p });
  if (actual.length !== expect.length) return false;
  return crypto.timingSafeEqual(actual, expect);
}

const DUMMY_HASH =
  "scrypt$4096$8$1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

export async function verifyPasswordDummy(password) {
  await verifyPassword(password, DUMMY_HASH);
}
