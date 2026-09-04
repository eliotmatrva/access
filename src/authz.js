import { AccessError, codes } from "./errors.js";

export function assertPermissions(catalog, list) {
  if (!Array.isArray(list)) {
    throw new AccessError(codes.INVALID, "permissions must be an array");
  }
  for (const p of list) {
    if (typeof p !== "string" || !p.trim()) {
      throw new AccessError(codes.INVALID, "permission must be a non-empty string");
    }
    if (!catalog.includes(p)) {
      throw new AccessError(codes.UNKNOWN_PERMISSION, `Unknown permission: ${p}`);
    }
  }
}

export function can(user, permission) {
  if (!user || user.status === "disabled") return false;
  return Array.isArray(user.permissions) && user.permissions.includes(permission);
}
