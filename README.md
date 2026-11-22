# Verify

**Status:** v0.2 implementation — working app, container, and GHCR pipeline.  
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
| `X-Proxy-Secret` | Production | Shared secret between proxy and app. Required by `compose.prod.yaml`; optional only for an mTLS-only deployment. |

**The proxy must:**

1. Authenticate every request.
2. **Strip any client-supplied copies** of these headers.
3. Inject them only after authentication.
4. Protect the proxy-to-app leg with mTLS or the shared secret.
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

- The session creator chooses **Full** or **Masked** detail.
- Full mode displays the number in the session identity cards.
- Masked mode shows `1990••••-••••`; a participant can explicitly share their own full number.
- The number is encrypted at rest with Fernet; the key is derived from `SECRET_KEY` or a separate `PN_ENCRYPTION_KEY`.
- It is **never** written to receipts, logs, analytics, URLs, or QR codes.
- The UI hides the number when the tab loses visibility; the user can show it again.
- Receipts always use the masked form.
- A privacy/DPIA review is still required before production.

If you do not need full display, set the default to masked in `app/templates/home.html` and remove the full option; the backend supports both.

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
# edit .env, then:
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
- masked-number reveal,
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

## License

MIT. See [LICENSE](LICENSE).
