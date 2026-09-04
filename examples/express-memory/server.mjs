import express from "express";
import { createAccess, MemoryStore } from "../../src/access.js";
import { createAccessRouter } from "../../src/express.js";

const SECRET = process.env.ACCESS_SECRET || "dev-secret-change-me-16+";
const PORT = Number(process.env.PORT) || 3000;

const access = createAccess({
  store: new MemoryStore(),
  secret: SECRET,
  permissions: ["admin", "edit", "view"],
});

await access.bootstrapAdmin({
  name: "Ada",
  email: "ada@example.com",
  password: process.env.ACCESS_BOOTSTRAP_PASSWORD || "password1",
  permissions: ["admin"],
});

const wired = createAccessRouter(access);
const app = express();
app.use(express.json());
app.use("/access", wired.router(express));
app.get("/health", (_req, res) => res.json({ ok: true }));
app.get("/secret", wired.requireAuth, (req, res) => res.json({ user: req.user }));
app.post("/publish", wired.require("edit"), (_req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`listening on http://127.0.0.1:${PORT}`);
  console.log("POST /access/login { email, password }");
});
