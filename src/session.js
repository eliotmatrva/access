import crypto from "node:crypto";

export function signToken(payload, secret) {
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const sig = crypto.createHmac("sha256", secret).update(body).digest("base64url");
  return `${body}.${sig}`;
}

export function readToken(token, secret) {
  if (!token || typeof token !== "string" || !token.includes(".")) return null;
  const i = token.lastIndexOf(".");
  const body = token.slice(0, i);
  const sig = token.slice(i + 1);
  if (!body || !sig) return null;
  const expect = crypto.createHmac("sha256", secret).update(body).digest("base64url");
  const a = Buffer.from(sig);
  const b = Buffer.from(expect);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    return JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

export function cookieFromReq(req, name) {
  const raw = String(req?.headers?.cookie || "");
  if (!raw) return "";
  const parts = raw.split(/;\s*/);
  for (const part of parts) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    if (part.slice(0, eq) === name) {
      try {
        return decodeURIComponent(part.slice(eq + 1));
      } catch {
        return part.slice(eq + 1);
      }
    }
  }
  return "";
}

export function sessionSetCookie(name, token, cookie) {
  const path = cookie.path || "/";
  const sameSite = cookie.sameSite || "Lax";
  const maxAge = Number(cookie.maxAgeSec) || 0;
  const secure = cookie.secure ? "; Secure" : "";
  return `${name}=${encodeURIComponent(token)}; Path=${path}; HttpOnly; SameSite=${sameSite}; Max-Age=${maxAge}${secure}`;
}

export function sessionClearCookie(name, cookie = {}) {
  const path = cookie.path || "/";
  return `${name}=; Path=${path}; HttpOnly; Max-Age=0`;
}
