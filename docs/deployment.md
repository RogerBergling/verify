# Deployment notes

**Status:** implementation notes for v0.2.  
**Related:** [README](../README.md), [Design](design.md), [Threat model](threat-model.md).

---

## 1. Container

```bash
docker pull ghcr.io/rogerbergling/verify:latest
```

Run behind the auth proxy:

```bash
docker run -d --name verify \
  -p 127.0.0.1:8080:8080 \
  -e AUTH_MODE=proxy \
  -e SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')" \
  -e COOKIE_SECURE=1 \
  -e BASE_URL=https://verify.example.se \
  -e PROXY_SHARED_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')" \
  -e DATA_DIR=/data \
  -v samsyn-data:/data \
  ghcr.io/rogerbergling/verify:latest
```

The app should **not** be published directly. Bind it to localhost or a private network, and let the proxy be the only route.

### Upgrading from the previous Samsyn deployment

The Compose project namespace and data volume remain `samsyn` so existing data is
reused. Remove the old container before starting the renamed service:

```bash
docker compose -f compose.prod.yaml down --remove-orphans
docker compose -f compose.prod.yaml pull
docker compose -f compose.prod.yaml up -d --force-recreate --remove-orphans
```

`down` without `-v` preserves the named volume. Do not add `-v` unless you intend
to delete the data.

---

## 2. Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `AUTH_MODE` | `proxy` | `proxy` for production, `dev` for local mock identities. |
| `SECRET_KEY` | required in proxy mode | Session/CSRF/receipt signing material and PN-encryption derivation. At least 32 characters. |
| `PN_ENCRYPTION_KEY` | derived from `SECRET_KEY` | Optional separate key for personal-number encryption. |
| `PROXY_SHARED_SECRET` | required by production Compose | Shared secret required in `X-Proxy-Secret`. Optional only when the proxy-to-app leg uses mTLS. |
| `COOKIE_SECURE` | true in proxy mode | Adds `Secure` to the session cookie. Set `0` only for local HTTP. |
| `COOKIE_NAME` | `__Host-verify_sid` when secure, else `verify_sid` | Session cookie name. The `__Host-` prefix requires `Secure`, `Path=/`, and no `Domain`. |
| `BASE_URL` | required | Public absolute URL used in invitation links, e.g. `https://verify.example.se`. The app refuses to start without it. |
| `ALLOWED_ORIGINS` | empty | Comma-separated additional browser origins accepted by the CSRF origin check, e.g. an alias hostname. The request’s own host is always accepted. |
| `PROXY_LOGOUT_URL` | unset | Redirect target for sign-out. |
| `DATA_DIR` | `./data` | SQLite data directory. Use a persistent volume in containers. |
| `DATABASE_PATH` | `$DATA_DIR/samsyn.db` | Override the database path. |
| `HOST` / `PORT` | `0.0.0.0` / `8080` | Listen address and port. |
| `VERIFICATION_TTL_SECONDS` | `600` | Default session lifetime (the UI defaults to 10 minutes and offers 5/10/15). |
| `AUTH_SESSION_TTL_SECONDS` | `43200` | App session lifetime. |
| `RATE_CREATE_PER_HOUR` | `20` | Session creation limit per user. |
| `RATE_JOIN_PER_HOUR` | `60` | Join attempt limit. |
| `RATE_CONFIRM_PER_MINUTE` | `60` | Confirmation limit. |
| `RATE_REVEAL_PER_MINUTE` | `20` | PN reveal limit. |
| `GITHUB_URL` | `https://github.com/RogerBergling/verify` | Footer link. |

**Secrets:** generate with a CSPRNG, store in a secret manager, and never commit them. Rotating `SECRET_KEY` invalidates existing app sessions and receipt HMACs; rotating the PN key makes existing encrypted personal numbers unreadable. Plan rotation accordingly.

---

## 3. Proxy header contract

The proxy must authenticate the request and inject exactly one value for each required header:

```http
X-User-Id: 8f2c1a...
X-Name: Alice
X-Last-Name: Andersson
X-Person-Id: 19900101-1234
X-Auth-Assurance: eid_auth
X-Auth-Org: Nordbank
X-Proxy-Secret: <optional shared secret>
```

Required:

- `X-User-Id` — stable, opaque subject. **Not** the personal number.
- `X-Name` — given name.
- `X-Last-Name` — surname.

Optional:

- `X-Person-Id` — personal number or comparable ID. If present, it is encrypted at rest and displayed according to the session's `pn_mode`.
- `X-Auth-Assurance` — `proxy`, `eid_auth`, or `eid_sign`. Defaults to `proxy`.
- `X-Auth-Org` — organisation label.
- `X-Proxy-Secret` — required only when `PROXY_SHARED_SECRET` is configured.

### The proxy must

1. Authenticate every request.
2. Remove **all** client-supplied identity headers before adding its own.
3. Add the headers only after authentication.
4. Use mTLS or the shared secret on the proxy-to-app leg.
5. Prevent direct access to the app port.
6. Preserve a single value per header; do not append.
7. Set the assurance header honestly.

### The app must

- Reject duplicate, empty, malformed, or overlong headers.
- Bind its own server-side session to the proxy subject.
- Rotate the app session if the subject changes.
- Never accept a user ID from a request body or query string.
- Fail closed if the identity is missing.

### Example: Traefik ForwardAuth

Traefik can forward authentication to an external service and copy selected response headers to the upstream request. The exact labels depend on your Traefik version and auth service:

```yaml
http:
  middlewares:
    verify-auth:
      forwardAuth:
        address: "http://auth-service:4181/verify"
        trustForwardHeader: false
        authResponseHeaders:
          - X-User-Id
          - X-Name
          - X-Last-Name
          - X-Person-Id
          - X-Auth-Assurance
          - X-Auth-Org
```

The auth service must return those headers only after validating the user's session, and Traefik must be the only route to the Verify container. Verify with the tests below; do not assume the middleware strips inbound headers.

### Example: nginx `auth_request`

`auth_request` can gate access, but nginx does not automatically copy arbitrary headers from the auth subrequest. Use `auth_request_set` for each header, and ensure the auth service does not echo client-supplied values. Alternatively, terminate authentication in a dedicated gateway (Envoy, OAuth2 Proxy, Authentik, Keycloak gatekeeper) that supports header injection and stripping.

### Example: OAuth2 Proxy

OAuth2 Proxy can pass `X-Auth-Request-User`, `X-Auth-Request-Email`, and similar headers. Map those to Verify's header names in your ingress/gateway, and set `X-Auth-Assurance` explicitly. Do not use the email as `X-User-Id` unless it is stable and opaque enough for your directory.

---

## 4. Header-boundary tests

Run these from **outside** the proxy:

```bash
# 1. Direct access must fail (connection refused or 403).
curl -i http://app-host:8080/

# 2. Forged identity must not authenticate.
curl -i -H 'X-User-Id: victim' http://app-host:8080/

# 3. Through the proxy, a forged header must be replaced/stripped.
curl -i -H 'X-User-Id: victim' https://verify.example.se/
```

Then, through the proxy as a legitimate user:

```bash
curl -i https://verify.example.se/api/me
```

The returned `subject` must be the proxy-authenticated subject, not `victim`.

Add these checks to CI or your deployment smoke tests.

---

## 5. Reverse proxy TLS and cookies

- Terminate TLS at the proxy.
- Set `COOKIE_SECURE=1` in production.
- Set `BASE_URL=https://...` so invite links use the public origin.
- Set `PROXY_LOGOUT_URL` if the proxy has a logout endpoint.
- Do not expose the app's `/healthz` publicly; it is intentionally unauthenticated for container orchestration.
- Keep the app's port on a private network.

---

## 6. Persistent data and backups

SQLite is used for v0.2. The project was renamed from Samsyn; the database file
name, Docker volume name, Compose project name, and encryption salt are retained
for compatibility with existing installations. Do not rename them without a
migration plan.

- `$DATA_DIR/samsyn.db` — users, sessions, confirmations, events, receipts.
- WAL files may exist next to it.

Back up the volume consistently (SQLite backup API or a filesystem snapshot). Test restore. For multi-instance deployments, move to PostgreSQL and shared rate limiting; SQLite is a single-writer database and is not appropriate for horizontal scaling.

Retention is not automated beyond expiry of active verifications and auth sessions. Add a retention job for receipts/events according to your policy before production.

---

## 7. GHCR

The workflow publishes:

```
ghcr.io/<owner>/<repo>:latest
ghcr.io/<owner>/<repo>:sha-<commit>
ghcr.io/<owner>/<repo>:<tag>
```

For this repository, the planned image is:

```
ghcr.io/rogerbergling/verify
```

If the package is private:

```bash
echo "$GITHUB_TOKEN" | docker login ghcr.io -u <github-user> --password-stdin
```

Set package visibility in GitHub → Packages. A private repository does not automatically make the package public.

The workflow builds `linux/amd64` and `linux/arm64`, with SBOM and provenance. It runs on `main`, tags `v*`, and manual dispatch. The first push to `main` creates the package.

---

## 8. eID / BankID / Freja

v0.2 does not integrate BankID or Freja. It consumes the proxy's identity assertion. If the proxy is already BankID/Freja-based, set `X-Auth-Assurance` to `eid_auth` and the app will label it accordingly. If you need signing or a direct eID integration later:

- BankID: RP API v6, mTLS, `/auth` or `/sign`, `/collect`, animated QR, production agreement via a bank or broker.
- Freja: OIDC for authentication; separate Signature API for signing; production contract and client certificate.
- Keep client certificates server-side.
- Validate signatures, certificate chains, and OCSP.
- Add an eID adapter instead of hardcoding a provider.

Test environments are free; production is not. See the README section on eID options and the notes in `docs/design.md`.

---

## 9. Production security checklist

- [ ] App port is private; only the proxy can reach it.
- [ ] Proxy strips client-supplied identity headers; tested.
- [ ] Proxy-to-app leg uses mTLS or `PROXY_SHARED_SECRET`.
- [ ] `SECRET_KEY` is strong and stored in a secret manager.
- [ ] `COOKIE_SECURE=1`, `BASE_URL=https://...`, and `ALLOWED_ORIGINS` cover every public hostname used to open the app.
- [ ] `X-Auth-Assurance` is set honestly.
- [ ] `DATA_DIR` is on a persistent volume; backups tested.
- [ ] Receipt/event retention policy implemented.
- [ ] DPIA/privacy review for full personal-number display.
- [ ] Rate limits and WAF/DDoS protection reviewed.
- [ ] Logs contain no personal numbers, codes, tokens, or cookies.
- [ ] `docker scout`/Trivy or equivalent scan is clean.
- [ ] Incident response and kill switch documented.
- [ ] Name/trademark clearance completed before public branding.
