export class AccessError extends Error {
  constructor(code, message, status = 400) {
    super(message);
    this.name = "AccessError";
    this.code = code;
    this.status = status;
  }
}

export function isAccessError(err) {
  return err instanceof AccessError;
}

export const codes = {
  UNAUTHENTICATED: "UNAUTHENTICATED",
  FORBIDDEN: "FORBIDDEN",
  BAD_CREDENTIALS: "BAD_CREDENTIALS",
  DISABLED: "DISABLED",
  NOT_FOUND: "NOT_FOUND",
  EMAIL_TAKEN: "EMAIL_TAKEN",
  UNKNOWN_PERMISSION: "UNKNOWN_PERMISSION",
  INVALID: "INVALID",
  EXPIRED: "EXPIRED",
  MISSING_SECRET: "MISSING_SECRET",
};
