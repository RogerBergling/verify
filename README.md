# Verify

**Project facts (2026-11-25):** version **0.2.0** · Python 3.11+ server-rendered app + SQLite · 18 unittest tests · MIT licensed.

**Status:** v0.2 implementation — working app, container, and GHCR pipeline. The
working tree contains post-v0.2.0 security hardening (masked PN default, proxy
fail-closed, placeholder-secret rejection); rebuild and republish the image
before relying on it.

**Product name:** Verify. It is a common word and is **not trademark-cleared**; see [docs/naming.md](docs/naming.md).  
**Design:** dark, clear interface inspired by [apps.bergling.net](https://apps.bergling.net), simplified for end users.

Verify is a web app for **mutual verification between people in a call**. Two authenticated people join a short session, see each other’s identity and assurance level, and each reads their **own** code aloud for the other to enter and verify. The result is an integrity-protected receipt.

It sits behind an existing secure proxy. The app has no password login of its own, but it still enforces authorization, session security, CSRF, rate limits, audit, and privacy.

---

## What is in the app

- Server-rendered pages with a dark/light theme, a simple two-action home screen, and responsive layout.
- Swedish and English UI. The server detects `Accept-Language` on first visit; the user can switch with **SV / EN** and the choice is remembered in a cookie.
- Real server-side sessions, SQLite persistence, CSRF protection, rate limits, and audit events.
- Proxy-header authentication (`X-User-Id`, `X-Name`, `X-Last-Name`, `X-Person-Id`).
- A development mode with mock identities for local testing.
- 1:1 call, customer-service, and in-person flows.
- Per-person 6-digit + 3-word verification code; each participant enters the other person’s code. Single-use 256-bit join token.
- Both participants must verify the other person’s code; one-sided verification never completes.
- A plain-language verification status panel shows both directions: “You verified their code” and “They verified your code.”
- Full personal number display as a controlled “sensitive” view, encrypted at rest, never logged, never written to receipts.
- Receipts with HMAC-SHA256 integrity, JSON download, and print/PDF.
- A plain-language Safety page explaining what is and is not verified.
- A How it works page covering what to share, what each person does, and who can hear the code.
- Dockerfile, Compose files, CI, and a GitHub Actions workflow that publishes to GHCR.

Group verification is deliberately not in v0.2. The data model and design leave room for it, but group roster verification needs its own phase.

---

## Quick start (local, no Node required)

Requirements: Python 3.11+ (3.14 recommended). No Node.js, npm, or frontend build step.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt

export AUTH_MODE=dev
export SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
export COOKIE_SECURE=0
export BASE_URL=http://127.0.0.1:8080
python3 -m app
```

Open <http://127.0.0.1:8080>. Choose a mock identity on the sign-in page. To simulate two people, use two tabs/windows and the **Open as Bob/Customer** button on the invite screen; the development link logs the second tab in as the counterpart.

Or use the included Compose file:

```bash
docker compose up --build
```

The app uses SQLite at `DATA_DIR/samsyn.db` (default `./data/samsyn.db`).

**Compatibility note:** the project was renamed from Samsyn, but the database
filename (`samsyn.db`), Docker volume (`samsyn-data`), legacy Compose project name
(`samsyn`), and encryption salt are intentionally retained so existing data keeps
working. Do not rename them without a migration plan.

---

## Development mode vs production proxy mode

### `AUTH_MODE=dev`

- Adds a mock sign-in page with Alice, Bob, Anna (Nordbank agent), and Erik (customer).
- `/dev/login` exists only in dev mode.
- **Never expose dev mode to the internet.** Anyone who can reach it can choose an identity.

### `AUTH_MODE=proxy` (default)

The app expects the reverse proxy / IdP to authenticate the user and inject:

| Header | Required | Notes |
|---|---|---|
| `X-User-Id` | Yes | Stable, opaque subject. Do not use the personal number. |
| `X-Name` | Yes | Given name. |
| `X-Last-Name` | Yes | Surname. |
| `X-Person-Id` | No | Swedish personal number or comparable ID. Sensitive; stored encrypted. |
| `X-Auth-Assurance` | No | `proxy`, `eid_auth`, or `eid_sign`. Defaults to `proxy`. |
| `X-Auth-Org` | No | Organisation/company label for customer-service flows. |
| `X-Proxy-Secret` | Yes | Shared secret between proxy and app. Required by the current code in `AUTH_MODE=proxy`, even when mTLS is used. Must match `PROXY_SHARED_SECRET`. |

**The proxy must:**

1. Authenticate every request.
2. **Strip any client-supplied copies** of these headers.
3. Inject them only after authentication.
4. Protect the proxy-to-app leg with mTLS and/or a private network; the app also requires the shared secret.
5. Prevent direct access to the app port.
6. Set `X-Auth-Assurance` honestly if the identity is eID-verified.

If the app is directly reachable, anyone can forge `X-User-Id`. The app cannot distinguish a forged header from a proxy-injected one. Network isolation and proxy header stripping are mandatory.

Production environment example:

```bash
AUTH_MODE=proxy
SECRET_KEY=<long random secret>
PN_ENCRYPTION_KEY=<optional separate 32+ char key>
PROXY_SHARED_SECRET=<required proxy shared secret in production Compose>
COOKIE_SECURE=1
BASE_URL=https://verify.example.se
ALLOWED_ORIGINS=https://verify.example.se,https://verify-alias.example.se
PROXY_LOGOUT_URL=https://sso.example.se/logout
DATA_DIR=/data
```

`BASE_URL` is the **public address used in invitation links**. It is required;
the app will not fall back to an internal container or proxy host. For example,
if users open `https://verify.example.se`, set exactly that.

**If you see “Request origin is not allowed” when starting a verification:**
open the app on the same URL you configured in `BASE_URL`, or add the browser’s
origin to `ALLOWED_ORIGINS` (comma-separated). The request’s own host is accepted
automatically, so this is usually a `localhost` vs `127.0.0.1`, port, or proxy
hostname mismatch.

### Production secrets

`compose.prod.yaml` reads these values from `.env` (or the process environment):

| Variable | Required | Purpose | Rotating it |
|---|---|---|---|
| `SECRET_KEY` | Yes | Internal app key for receipt HMACs, IP/UA hashing, join-token encryption, and personal-number encryption when no separate PN key is set. The proxy does not need it. | Existing receipts become unverifiable, and encrypted join tokens/personal numbers become unreadable. |
| `PN_ENCRYPTION_KEY` | No, recommended | Separate key for personal-number encryption. If omitted, the key is derived from `SECRET_KEY`. | Existing encrypted personal numbers become unreadable. Set it before the first production start. |
| `PROXY_SHARED_SECRET` | Yes | Shared secret sent by the proxy in `X-Proxy-Secret`. It proves the request came from the proxy, not from something else that can reach the app port. | Must be changed in the proxy and the app together. |

Generate them with a CSPRNG:

```bash
python3 -c 'import secrets; print(secrets.token_urlsafe(48))'  # SECRET_KEY
python3 -c 'import secrets; print(secrets.token_urlsafe(48))'  # PN_ENCRYPTION_KEY
python3 -c 'import secrets; print(secrets.token_urlsafe(32))'  # PROXY_SHARED_SECRET
```

`SECRET_KEY` and `PROXY_SHARED_SECRET` must be different. Keep `.env` at mode `600`, owned by the deploy user, and never commit it. Compose interpolation also places these values in the container environment, where they are visible to anyone who can run `docker inspect`; protect the host or inject them from a secret manager at deploy time.

`AUTH_MODE`, `COOKIE_SECURE`, `DATA_DIR`, and `PORT` are pinned in `compose.prod.yaml` (`proxy`, `1`, `/data`, `8080`). Setting them in `.env` does not override the Compose values.

**Compose note:** `compose.prod.yaml` does not currently pass `ALLOWED_ORIGINS` into the container. If you use alias hostnames, add this under `environment:`:

```yaml
ALLOWED_ORIGINS: ${ALLOWED_ORIGINS:-}
```

Otherwise the value in `.env` has no effect. A single public hostname is normally covered by `BASE_URL` and the request host.

### Behind MobilityGuard OneGate

Verify has no OneGate-specific integration. OneGate must authenticate the user, strip client-supplied identity headers, and inject the exact header names above. Publish Verify in OneGate as a web application with:

- **Public URL:** `https://verify.example.se` — must match `BASE_URL`.
- **Upstream:** the Verify container or host, e.g. `http://127.0.0.1:8080` if OneGate is on the same host, otherwise a private address.
- **SSO method:** HTTP X-Headers.

Map the authenticated user to the header contract:

| Header | OneGate value |
|---|---|
| `X-User-Id` | Stable, opaque subject, e.g. `PARM{mguid}` or an objectGUID. Do not use the personal number or a changeable email address. |
| `X-Name` | Given name, e.g. the attribute mapped to `givenName`. |
| `X-Last-Name` | Surname, e.g. `sn`. |
| `X-Person-Id` | Optional personal number, if OneGate has a trustworthy attribute. Verify encrypts it at rest. |
| `X-Auth-Assurance` | `proxy` for normal SSO/MFA; `eid_auth` only if OneGate actually verified an eID; `eid_sign` only for signing. |
| `X-Auth-Org` | Optional organisation label for customer-service flows. |
| `X-Proxy-Secret` | The same value as `PROXY_SHARED_SECRET` in `.env`. |

OneGate custom headers typically use `PARM{...}` values, for example:

```text
X-User-Id        PARM{mguid}
X-Name           PARM{ldap1}
X-Last-Name      PARM{ldap2}
X-Person-Id      PARM{ldap3}
X-Auth-Assurance proxy
X-Auth-Org       PARM{ldap4}
X-Proxy-Secret   <PROXY_SHARED_SECRET>
```

Adjust the `PARM{...}` names to your OneGate field mapping. The left-hand names must be exact. `X-Userid` is not `X-User-Id`.

OneGate must also:

1. Overwrite or remove any client-supplied copy of every identity header and `X-Proxy-Secret`.
2. Send exactly one value per header; Verify rejects duplicates.
3. Preserve the original path through login, especially `/join/<token>`.
4. Terminate TLS and keep the OneGate-to-Verify leg on loopback or a private network.
5. Not expose `/healthz` publicly.

`compose.prod.yaml` binds the app to `127.0.0.1:8080`. If OneGate runs on another host, change the bind to a private address, for example `"10.0.0.10:8080:8080"`, or place both on the same private Docker network. Firewall the port so only OneGate can reach it; never publish `0.0.0.0:8080`.

Smoke test from outside the proxy:

```bash
# Direct access must fail
curl -i http://app-host:8080/

# A forged identity header must not authenticate
curl -i -H 'X-User-Id: victim' https://verify.example.se/api/me

# A wrong shared secret must be rejected
curl -i -H 'X-Proxy-Secret: wrong' http://app-host:8080/
```

`/api/me` must return the OneGate-authenticated subject, not `victim`. `/api/security-check` also reports the forged header and the active auth mode.

### Why `X-Proxy-Secret` is required

In proxy mode the app trusts `X-User-Id` and the other identity headers; it has no login of its own. If anything other than the proxy can reach the app port, it can forge those headers and impersonate any user. Network isolation is the primary control, but firewall and Docker network mistakes happen. The shared secret is a fail-closed second gate: a caller must both reach the app and know the secret.

The secret authenticates only the proxy-to-app hop. It does not authenticate the end user, and it is a static bearer secret with no replay protection. Send it only over TLS, mTLS, loopback, or a private network. If it leaks, rotate it in OneGate and `.env` together.

---

## Theme modes

`APP_THEME` sets the first-visit theme. The theme toggle saves the visitor's
explicit choice, which overrides this default.

| Value | Behavior |
|---|---|
| `dark` | Dark theme (default) |
| `light` | Light/white theme |
| `system` | Follow the browser/OS `prefers-color-scheme` |

Set it in `.env` or Compose:

```yaml
environment:
  APP_THEME: ${APP_THEME:-dark}
```

Invalid values fall back to `dark`. The default is rendered into the page and
resolved before first paint, so there is no theme flash.

## Full personal number: the decision and the controls

The product decision is that the full personal number **must be displayable** during verification. The implementation treats that as a high-risk feature:

- **Masked is the default.** The session creator can choose masked or full detail, but the choice never exposes another participant's number.
- Each participant always sees their **own** number. Another participant's full number is shown only after that person explicitly chooses **Reveal**.
- Masked mode shows `1990••••-••••` to the other participant. Full mode still requires the other person's explicit reveal.
- The number is encrypted at rest with Fernet; the key is derived from `SECRET_KEY` or a separate `PN_ENCRYPTION_KEY`.
- It is **never** written to receipts, logs, analytics, URLs, or QR codes.
- The UI hides the number when the tab loses visibility; the user can show it again.
- Receipts always use the masked form.
- A privacy/DPIA review is still required before production.

---

## Docker

```bash
docker build -t verify:dev .

docker run --rm -p 8080:8080 \
  -e AUTH_MODE=dev \
  -e SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')" \
  -e COOKIE_SECURE=0 \
  -e BASE_URL=http://localhost:8080 \
  -e DATA_DIR=/data \
  -v samsyn-data:/data \
  verify:dev
```

The image runs as a non-root user, exposes port `8080`, and has a `/healthz` health check.

For production:

```bash
cp .env.example .env
chmod 600 .env
# edit .env, then:
docker compose -f compose.prod.yaml pull
docker compose -f compose.prod.yaml up -d
```

The production compose file expects the image `ghcr.io/rogerbergling/verify:latest`. Change the image if the repository name differs.

**Upgrading from Samsyn:** the Compose project namespace and data volume remain
`samsyn` on purpose. Remove the old container before starting the renamed service:

```bash
docker compose -f compose.prod.yaml down --remove-orphans
docker compose -f compose.prod.yaml pull
docker compose -f compose.prod.yaml up -d --force-recreate --remove-orphans
```

Do not use `down -v`; that would delete the existing data volume.

---

## GHCR (GitHub Container Registry)

The workflow `.github/workflows/container.yml` builds on pushes to `main`, version tags `v*`, and manual dispatch. It publishes multi-arch images (`linux/amd64`, `linux/arm64`) with SBOM and provenance:

```
ghcr.io/rogerbergling/verify:latest
ghcr.io/rogerbergling/verify:sha-<commit>
ghcr.io/rogerbergling/verify:v0.2.0
```

The workflow uses the repository `GITHUB_TOKEN` with `packages: write`. If the package is private, authenticate before pulling:

```bash
echo "$GITHUB_TOKEN" | docker login ghcr.io -u <github-user> --password-stdin
docker pull ghcr.io/rogerbergling/verify:latest
```

Package visibility is controlled in the GitHub package settings. A private repository does **not** automatically make the package public; GitHub packages are private by default.

---

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The suite covers:

- health and dev login,
- CSRF enforcement and origin acceptance/rejection,
- Swedish/English language detection and SV/EN switching,
- forged `X-User-Id` ignored in dev,
- full create/join/verify-code/receipt flow with unique per-person codes,
- wrong or missing counterpart code rejected,
- configured public `BASE_URL` used for invitation links,
- single-use join tokens and IDOR,
- mismatch with no receipt,
- masked-number reveal and no disclosure in full mode without an explicit reveal,
- `PROXY_SHARED_SECRET` required when `AUTH_MODE=proxy`, and known placeholder secrets rejected,
- server-side expiry,
- personal-number encryption at rest,
- proxy-mode header authentication and shared-secret rejection.

---

## Project layout

```
app/
  __main__.py        entry point and cleanup worker
  config.py          environment configuration
  db.py              SQLite schema and persistence helpers
  auth.py            proxy/dev identity resolution, sessions, CSRF
  verification.py    session state machine, codes, confirmations, receipts
  security.py        tokens, encryption, masking, HMAC, validation
  web.py             HTTP server, routes, security headers, rate limits
  templates/         Jinja2 pages
  static/            design-system CSS, theme, app JS, favicon
tests/
  test_app.py        end-to-end HTTP tests
docs/
  design.md          product/architecture design
  threat-model.md    STRIDE analysis and residual risks
  naming.md          preliminary name check
  deployment.md      proxy and container deployment notes
Dockerfile
compose.yaml         local dev
compose.prod.yaml    production image
.github/workflows/   CI + GHCR
```

---

## Security boundaries and limitations

Verify proves **account presence in the same session**, not the call channel:

- It does **not** prove that the voice or video stream is authentic.
- It does **not** prove that a device or account is not compromised.
- It does **not** detect a group-call listener who never joins the app.
- A corporate SSO name is not a legal identity; the assurance label stays honest.
- BankID/Freja are **not** integrated in v0.2. If the proxy provides eID assurance, set `X-Auth-Assurance`; otherwise the app labels the identity as proxy-authenticated.
- Receipts are audit records, not qualified electronic signatures.

Read [docs/security-model notes](docs/threat-model.md) and the in-app `/security` page.

---

## Naming

The product name is now **Verify**. It is a common English/Swedish word, so trademark and domain clearance is still required before commercial branding. The previous working name **Samsyn** was dropped because of prior use in the same space (IKEA Samsyn, Sambruk’s Samsyn, Samsyn AB, samsyn.io). See [docs/naming.md](docs/naming.md) for the history and clearance checklist.

---

## Documentation

- [Design](docs/design.md)
- [Threat model](docs/threat-model.md)
- [Naming](docs/naming.md)
- [Deployment](docs/deployment.md)


## AI assistance

Developed with AI assistance and human review. The maintainer defines the
requirements, threat model and acceptance criteria; AI helps write and refactor
code; the maintainer runs, tests and verifies the result. The software is
provided as-is, without warranty.

## License

MIT. See [LICENSE](LICENSE).
