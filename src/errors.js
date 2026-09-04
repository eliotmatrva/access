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
