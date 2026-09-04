# Principles

If a change violates this file, do not make it.

1. Library, not an identity product. Apps import it. Users visit the app, not Access.
2. No host-app knowledge. Permissions are opaque strings the host registers.
3. Tenancy is the Store the host passes in. No tenant column in core.
4. V1 sign-in is a password plus a signed HttpOnly cookie. Not JWT in localStorage.
5. Email sending is the host's job. Invites return a token.
6. ESM, no bundler, `node --test`, Node 20+.
7. Core has zero runtime dependencies. Express and pg are optional.
8. Never return a password hash. Client-supplied user ids are untrusted; the session is the source.
