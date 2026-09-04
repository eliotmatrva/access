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

await access.bootstrapAdmin({
  name: "Ada",
  email: "ada@example.com",
  password: process.env.ACCESS_BOOTSTRAP_PASSWORD,
  permissions: ["admin"],
});

const { user, token } = await access.login("ada@example.com", "password1");
const me = await access.userFromToken(token);
access.can(me, "admin"); // true
```

### Express

```js
import express from "express";
import { createAccess, MemoryStore } from "@eliotmatrva/access";
import { attachAccess } from "@eliotmatrva/access/express";

const access = createAccess({
  store: new MemoryStore(),
  secret: process.env.ACCESS_SECRET,
  permissions: ["admin", "edit", "view"],
});
const wired = attachAccess(access);

const app = express();
app.use(express.json());
app.use("/access", wired.router(express));
app.get("/secret", wired.requireAuth, (req, res) => res.json({ user: req.user }));
app.post("/publish", wired.require("edit"), (req, res) => res.json({ ok: true }));
```

Routes mounted by the router: `POST /login`, `POST /logout`, `GET /me`, `POST /change-password`, `GET /users`, `POST /users`.

### Postgres

```js
import { createAccess } from "@eliotmatrva/access";
import { PostgresStore } from "@eliotmatrva/access/pg";

const store = new PostgresStore(pool);
await store.migrate();
const access = createAccess({ store, secret: process.env.ACCESS_SECRET });
```

Tables: `access_user`, `access_credential`, `access_invite`. Schema lives in `sql/schema.sql`.

## What this is not

Not a website people visit to sign in. Not Google / Auth0 / Okta. Each app that installs Access keeps its own users unless you point two apps at the same database on purpose.

## Tests

```bash
npm test
```
