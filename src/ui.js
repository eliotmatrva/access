/**
 * Tiny vanilla helpers. Not a component framework.
 * Hosts can keep their own markup and only use bindLoginForm.
 */

export function loginFormHtml({
  action = "/auth/login",
  emailName = "email",
  passwordName = "password",
  submitLabel = "Sign in",
} = {}) {
  return `<form data-access-login method="post" action="${escapeHtml(action)}">
  <label>Email <input name="${escapeHtml(emailName)}" type="email" autocomplete="username" required /></label>
  <label>Password <input name="${escapeHtml(passwordName)}" type="password" autocomplete="current-password" required /></label>
  <button type="submit">${escapeHtml(submitLabel)}</button>
</form>`;
}

/**
 * @param {HTMLFormElement} form
 * @param {{ endpoint: string, onOk?: (body: object) => void, onError?: (body: object) => void }} opts
 */
export function bindLoginForm(form, opts) {
  if (!form || !opts?.endpoint) return;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    const email = String(data.get("email") || data.get("username") || "");
    const password = String(data.get("password") || "");
    const res = await fetch(opts.endpoint, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ email, password }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) {
      if (opts.onError) opts.onError(body);
      return;
    }
    if (opts.onOk) opts.onOk(body);
  });
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&")
    .replace(/"/g, """)
    .replace(/</g, "<")
    .replace(/>/g, ">");
}
