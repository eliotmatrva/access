export function publicUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    status: row.status,
    permissions: [...(row.permissions || [])],
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

export function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}
