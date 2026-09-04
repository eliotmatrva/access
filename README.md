# Access

Create people. Sign them in. Ask if they may do a thing.

A library an app installs — not a login website. Same kind of package as pals.

## Install

```bash
npm install github:eliotmatrva/access
```

In `package.json`:

```json
{
  "dependencies": {
    "@eliotmatrva/access": "github:eliotmatrva/access"
  }
}
```

Pin a commit SHA once you care about a stable cut.

## Use

```js
import { createAccess, MemoryStore } from "@eliotmatrva/access";

const access = createAccess({
  store: new MemoryStore(),
  secret: process.env.ACCESS_SECRET,
  permissions: ["admin", "edit", "view"],
});

await access.ready();

await access.bootstrapAdmin({
  name: "Ada",
  email: "ada@example.com",
  password: process.env.ACCESS_BOOTSTRAP_PASSWORD,
  permissions: ["admin"],
});

const { user, token } = await access.login("ada@example.com", "password1");
const me = await access.authenticate(token);
access.can(me, "admin"); // true
```

### Express

```js
import express from "express";
import { createAccess, MemoryStore } from "@eliotmatrva/access";
import { createAccessRouter } from "@eliotmatrva/access/express";

const access = createAccess({
  store: new MemoryStore(),
  secret: process.env.ACCESS_SECRET,
  permissions: ["admin", "edit", "view"],
});
const wired = createAccessRouter(access);

const app = express();
app.use(express.json());
app.use("/access", wired.router(express));
app.get("/secret", wired.requireAuth, (req, res) => res.json({ user: req.user }));
app.post("/publish", wired.require("edit"), (req, res) => res.json({ ok: true }));
```

Routes mounted by the router: `POST /login`, `POST /logout`, `GET /me`, `POST /change-password`, `GET /users`, `POST /users`, `POST /invites`, `POST /invites/accept`.

### Postgres

```js
import { createAccess } from "@eliotmatrva/access";
import { PostgresStore } from "@eliotmatrva/access/pg";

const store = new PostgresStore(pool);
await store.migrate();
const access = createAccess({
  store,
  secret: process.env.ACCESS_SECRET,
  permissions: ["admin", "edit", "view"],
});
await access.ready();
```

Tables: `access_user`, `access_credential`, `access_session`, `access_invite`. Schema lives in `sql/schema.sql`.

## API surface

- `createAccess({ store, secret, permissions, sessionTtlSec?, inviteTtlSec?, cookieName? })`
- `access.ready()`
- `access.bootstrapAdmin({ name, email, password, permissions })`
- `access.login(email, password)` → `{ user, token, ... }`
- `access.logout(token)`
- `access.authenticate(token)` / `access.userFromToken(token)`
- `access.require(permission)` → async (token) => user
- `access.can(user, permission)`
- `access.changePassword(userId, current, next)`
- Admin: `listUsers`, `createUser`, `updateUser`, `disableUser`, `createInvite`, `acceptInvite`
- Stores: `MemoryStore`, `PostgresStore` (with `migrate()`)
- Express: `createAccessRouter(access)` → `{ router, authenticate, requireAuth, require }`

## What this is not

Not a website people visit to sign in. Not Google / Auth0 / Okta. Each app that installs Access keeps its own users unless you point two apps at the same database on purpose.

## Tests

```bash
npm test
```
