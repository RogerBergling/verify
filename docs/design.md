# Project Verify — Design Document

**Status:** Implemented as v0.2; design retained for review.  
**Version:** 0.2  
**Date:** 2026-11-18  
**Working title:** Project Verify. Product name is **Verify** by product-owner decision — see [naming.md](naming.md).  
**Audience:** Product owner, engineering, security, operations, legal/privacy.

---

## 0.1 Decision log

| # | Decision | Consequence |
|---|---|---|
| D1 | Use the existing proxy + identity headers. | The proxy is the authentication boundary. The app still enforces authorization, CSRF, sessions and rate limits. |
| D2 | The claim is “both authenticated accounts are present in the same session.” | The app does not claim legal identity or call-channel integrity. |
| D3 | Support 1:1, customer service and in-person in v0.2; group is phase 2. | Group roster verification is designed but not implemented. |
| D4 | Rename the project to **Verify** (2026-11-21). The previous name Samsyn was rejected due to prior use. | “Verify” is generic; trademark/domain clearance is still required before commercial branding. |
| D5 | Full personal number must be displayable. | Implemented as an encrypted-at-rest, in-session display with a masked default option; never in receipts or logs; privacy review required. |
| D6 | The proxy authenticates both employees and external customers. | Customer-service flows are in scope; verify the proxy’s actual assurance and coverage. |
| D7 | Implement with Python 3.14 + stdlib HTTP + Jinja2 + SQLite. | No Node build step; container is small. Postgres/Redis are future scaling work. |

---

## 0.2 Assumptions to confirm

This design depends on the answers below. Each is marked as an assumption, not a fact. If an assumption is wrong, the design changes.

| # | Assumption | Why it matters |
|---|---|---|
| A1 | The existing proxy is the **only ingress** to the app. It authenticates every request, strips any client-supplied identity headers, and communicates with the app over a trusted channel (mTLS or private network). | If the app is directly reachable, anyone can forge `x-userid` and become anyone. |
| A2 | `x-userid` is a stable, opaque identifier. It is not the personal number. | It is used as the primary external subject key. |
| A3 | `x-name` is the given name and `x-lastname` is the surname. | Display and matching logic. |
| A4 | `x-personid` is a Swedish personal number or a comparable national identifier. It is sensitive and optional for the core flow. | Determines masking, HMAC, and retention rules. |
| A5 | The proxy authenticates **all** participants who need the app, including external customers. | Confirmed by the product owner. Verify the proxy’s actual assurance and coverage. |
| A6 | v1 does not integrate with a call platform (Teams, Zoom, Google Meet, telephony). The app is a separate browser tab/PWA. | The app cannot see the call participant list or verify the audio/video channel. |
| A7 | Receipts are audit records, not legally binding signatures. BankID/Freja signing is an optional later phase. | Avoids overclaiming legal validity. |
| A8 | Hosting is in the EU. v0.2 uses SQLite; Postgres/Redis are future scaling work. | Privacy and architecture. |
| A9 | The interface supports Swedish and English; the server detects `Accept-Language` and the user can switch with SV/EN. | Copy, code words, accessibility. |
| A10 | v1 covers 1:1, customer service and in-person. Group calls are designed but scheduled for phase 2. | Scope control. |

**Resolved dependency:** the proxy authenticates both employees and external customers (D6). The remaining risk is whether its assurance is strong enough for the customer-service use case; label it honestly.

---

## 1. Summary

Project Verify is a web app that lets two or more authenticated people confirm that they are present together in a conversation. It is used alongside a call, not inside the call itself.

The app creates a short-lived verification session. Participants join through a one-time link, see each other’s identity and assurance level, and each reads their own 6-digit + 3-word code aloud. The other participant enters that code to verify them. The server records both directions and produces a receipt.

The app does not implement login, passwords, or user onboarding. It relies on an existing reverse proxy / identity provider. It does, however, enforce authorization, session security, CSRF protection, input validation, rate limits, audit, and privacy. The proxy is the authentication boundary; the app is still responsible for everything after authentication.

The app deliberately distinguishes:

- **account presence** — both authenticated accounts joined and confirmed;
- **legal identity** — only if the proxy/eID actually asserts it;
- **channel integrity** — not solved by this app;
- **attestation** — a receipt, optionally signed with BankID/Freja.

That distinction is central to the product’s honesty and to its security.

---

## 2. Goals and non-goals

### 2.1 Goals

1. Let an authenticated user create a verification session for a specific conversation.
2. Let the other participant(s) join through a one-time link or QR code.
3. Show each participant the other participant’s identity and an honest assurance level.
4. Generate a unique verification code per participant; no static shared secret.
5. Require independent confirmation from every required participant.
6. Bind confirmations to the participant roster and session state.
7. Produce a verifiable receipt for a successful verification.
8. Support many concurrent sessions safely.
9. Minimize personal data, especially the personal number.
10. Work on desktop and mobile browsers; be accessible.

### 2.2 Non-goals for v1

- Proving that call audio/video is unmodified or unrelayed.
- Replacing the call platform or providing the call itself.
- Identity proofing/onboarding or issuing identities.
- Being a password store or an IdP.
- Legal signatures or qualified electronic signatures.
- Integrating with call-platform participant lists.
- Group-call roster integration.
- International eID coverage.
- Recording or transcribing the call.

Some of these may become later phases. They are explicitly out of scope now to prevent overclaiming.

---

## 3. Definitions

| Term | Meaning |
|---|---|
| **Authentication** | Establishing which account is making a request. Delegated to the proxy. |
| **Authorization** | Deciding whether that account may perform an action on a specific resource. Owned by the app. |
| **Assurance** | How strongly the identity was established. The proxy may assert it; the app must not invent it. |
| **Mutual verification** | Both participants see each other’s identity and independently confirm presence in the same session. |
| **Channel integrity** | Whether the call audio/video is authentic and unmodified. Not solved by this app. |
| **Attestation** | A record that the verification happened, optionally signed. |
| **Join token** | A high-entropy, single-use bearer token that lets a participant enter a session. It is not spoken aloud. |
| **Verification code** | A short human-comparable code owned by one participant and read aloud to the other. The other participant enters it to verify the owner. It is not used to join or authenticate. |
| **Roster** | The set of participants in a session, with their identities and assurance levels. |
| **Roster version** | A monotonically increasing number that changes when the participant set changes. Confirmations are bound to it. |
| **Assurance label** | The user-facing description of how identity was established. |
| **Receipt** | A server-generated record of a successful verification. |

### 3.1 The four-layer model

```
Layer 1: Authentication      Who is logged in?                  Proxy / eID
Layer 2: Mutual verification Are both accounts present?          This app
Layer 3: Channel integrity   Is the call audio/video authentic?  Call platform / call crypto
Layer 4: Attestation         Is there proof it happened?         This app / eID signature
```

This app owns layers 2 and 4. It consumes layer 1. It does not claim layer 3.

---

## 4. Users and scenarios

### 4.1 Personas

| Persona | Description | Needs |
|---|---|---|
| **Initiator** | Starts a verification session | Create, invite, see the other participant, confirm, get receipt |
| **Responder** | Joins an existing session | Join safely, see the initiator’s identity, confirm, get receipt |
| **Agent** | Customer-service employee | Initiate, see the customer’s identity, confirm, keep an audit trail |
| **Customer** | External person in a service call | Join safely, see the company/agent identity, confirm, not be phished |
| **Host** | Creates a group session | Set expected participants, lock the roster, confirm the group |
| **Participant** | Member of a group session | See the roster, confirm the roster and code |
| **Support/Admin** | Operates the service | View audit, revoke sessions, handle incidents (least privilege) |

### 4.2 Scenario A — 1:1 remote call (primary)

**Preconditions:** Both users are authenticated by the proxy. They are in a voice or video call. One of them has the app open.

**Flow:**

1. Alice creates a session. The app shows a join link and expiry; Alice gets her own code, and Bob gets a different code when he joins.
2. Alice shares the link in the call chat or shows the QR code.
3. Bob opens the link. The proxy authenticates him. He sees Alice’s identity card and assurance label.
4. Bob accepts. Alice sees “Bob Berg joined” with Bob’s identity and assurance label.
5. Each participant sees only their own code and words.
6. Alice reads her code aloud; Bob enters it in his app. Bob reads his code aloud; Alice enters it in her app.
7. The server verifies each entered code against the other participant’s code. When both directions are correct, it creates a receipt.

**What is proven:** both authenticated accounts joined the same session, saw each other’s identity, and each verified the other person’s code.

**Limitations:** the app does not prove the voice is authentic. If Mallory relays the call between Alice and Bob, both may still see each other in the app. See the threat model.

### 4.3 Scenario B — customer service (asymmetric)

**Preconditions:** The agent is authenticated. The customer is authenticated by the proxy or by an eID/customer IdP. The customer may be on a phone call, not video.

**Flow:**

1. The agent creates a session from the company’s app.
2. The app shows the company’s brand, the agent’s identity, and a link/code.
3. The agent sends the link by SMS, email, or the call platform’s chat, or reads a short reference while the customer opens the app.
4. The customer opens the app, authenticates, and sees: “You are verifying with [Company] — agent [Name].”
5. The customer confirms. The agent sees the customer’s identity and assurance label.
6. The customer reads their own code; the agent enters it. The agent reads theirs; the customer enters it.
7. A receipt is stored for the company’s audit.

**Anti-phishing rule:** the customer must never read a verification code back to an inbound caller. The company initiates; the customer enters or confirms in the app. The app copy must say this explicitly.

**Dependency:** external customers must be able to authenticate. If the existing proxy is employee-only, this scenario needs a customer IdP or eID before it can ship.

### 4.4 Scenario C — in-person

**Preconditions:** Both people are physically present, each with a device, or one device with a safe handover.

**Flow:**

1. Alice creates a session and shows a QR code.
2. Bob scans it with his phone; the proxy authenticates him.
3. Both see each other’s identity and each gets their own code.
4. Each reads their own code aloud and enters the other person’s code.

**What is proven:** the accounts belong to the people present, assuming devices are not shared or compromised. The code comparison is less important than in a remote call, but still useful.

**Limitations:** shoulder surfing; shared devices; one-device handover is risky and should require re-authentication.

### 4.5 Scenario D — group call (phase 2)

**Preconditions:** A host creates a session for a group. Participants join the app. The call platform is separate.

**Flow:**

1. The host creates a group session and sets an expected participant count, or leaves it open.
2. Participants join via link/QR.
3. The host reviews the roster and locks it.
4. The app computes a roster version and displays a group verification code/words.
5. Each participant sees the roster, compares the code, and confirms the roster and code.
6. If the roster changes after lock, the version increments and all confirmations are invalidated; everyone re-confirms.
7. The server marks the group verified when every required participant has confirmed the current roster version.

**What is proven:** everyone who joined the app saw the same roster and confirmed it.

**Limitations:** an uninvited listener in the call who never joins the app is invisible. Without call-platform integration, the app cannot compare its roster to the call roster. The UI must say “verified participants in this app session”, not “everyone in the call is verified.”

### 4.6 Scenario E — high-assurance step-up (later phase)

At join or confirmation time, a participant authenticates with BankID/Freja and optionally signs a canonical statement. The receipt then carries an eID signature and a higher assurance label. This is the strongest practical option in Sweden, but it requires contracts, certificates, and additional UX. It is not required for the core “both present” claim.

---

## 5. Trust model

### 5.1 Architecture trust boundaries

```
Alice browser ─┐
               ├─ TLS ─> Auth proxy / IdP ──(trusted identity)──> BFF / app ──> Postgres
Bob browser   ─┘             │                                      │
                             └─ session cookie                      └─ SSE / WebSocket
BankID / Freja <── mTLS ── BFF (future, server-side only)
```

| Boundary | Trust | Controls |
|---|---|---|
| Browser ↔ proxy | Untrusted network | TLS, HSTS, secure cookies, CSRF, CSP |
| Proxy ↔ app | Trusted network | mTLS or private network; signed headers/JWT; proxy strips inbound identity headers |
| App ↔ database | Private network | Credentials, encryption at rest, least privilege, backups |
| App ↔ eID provider | External trust | mTLS, signature verification, certificate validation, contract |
| App ↔ browser | Untrusted client | Server-side authorization; never trust client-supplied user IDs |

### 5.2 Identity header contract

The proxy currently provides four headers. The app should treat them as **assertions from the proxy**, not as facts from the browser.

| Header | Required | Format | Handling |
|---|---|---|---|
| `x-userid` | Yes | Opaque string, 1–128 chars | Primary subject key. Reject empty/duplicate/oversized values. |
| `x-name` | Yes | UTF-8, 1–100 chars | Given name. Escape on output. |
| `x-lastname` | Yes | UTF-8, 1–100 chars | Surname. Escape on output. |
| `x-personid` | Optional | National ID format | Sensitive. HMAC at ingress; mask for display; never log. |
| `x-auth-issuer` | Recommended | String | Which IdP/proxy asserted the identity. |
| `x-auth-assurance` | Recommended | Enum | `proxy`, `eid_auth`, `eid_sign`. |
| `x-auth-time` | Recommended | ISO-8601 | When the assertion was made. |
| `x-auth-signature` | Recommended | JWS/HMAC | Integrity of the assertion; validate before use. |

**Rules:**

1. Exactly one value per header. Reject duplicate headers and comma-joined values.
2. Reject control characters, CR/LF, and overlong values.
3. Normalize Unicode (NFC) before storage/display; still treat names as untrusted input.
4. Do not accept `x-userid` from the browser. The BFF must only read it from the proxy-to-app request.
5. If the proxy cannot sign or mTLS the assertion, the app must be network-isolated and the trust boundary documented. This is weaker; treat it as a compensating control.
6. If `x-personid` is absent, the app must still work. It is not required for the core flow.
7. If `x-userid` changes within an existing BFF session (shared device, spoofing), invalidate the session and force re-authentication.

### 5.3 Assurance levels and labels

The app must not invent assurance. It displays what the proxy/eID asserts.

| Level | Source | UI label | Meaning |
|---|---|---|---|
| `none` | No valid assertion | — | Cannot participate. |
| `proxy` | Existing SSO/proxy | “Signed in via [proxy]” | The proxy authenticated the account. This may be a corporate directory account, not a legal identity. |
| `eid_auth` | BankID/Freja authentication | “BankID-verified” / “Freja-verified” | The person authenticated with a verified eID. |
| `eid_sign` | BankID/Freja signature | “Signed with BankID/Freja” | The person signed a statement at verification time. |

If the proxy is BankID/Freja-based but does not expose an assurance claim, the app cannot safely label it as eID-verified. It must default to the weaker label, or the proxy must add an assurance claim.

### 5.4 What the proxy must guarantee

- It authenticates every request to the app.
- It strips any client-supplied `x-userid`, `x-name`, `x-lastname`, `x-personid`, and related headers.
- It adds identity headers only after successful authentication.
- It does not allow direct access to the app’s network/port.
- It invalidates its session on logout and after a defined idle period.
- It does not allow a user to change their `x-userid` mid-session.
- It provides an issuer/assurance claim, or the app must label the identity as unverified.

### 5.5 What the app must guarantee

- It creates its own BFF session after validating the proxy assertion.
- It authorizes every request against the BFF session and resource ownership.
- It never trusts a `userId` from a request body or query string.
- It never writes the full personal number to logs, analytics, URLs, QR codes, or receipts.
- It returns a participant’s own full personal number in their session view. Another participant’s full number is returned only after that person explicitly reveals it. The value is encrypted at rest and hidden when the tab loses visibility.
- It fails closed when the identity assertion is missing, malformed, duplicated, or expired.
- It rate-limits session creation, joins, and confirmations.
- It records an audit event for every state change.

---

## 6. Product flows

### 6.1 1:1 remote flow

```
Alice (browser)          BFF / app                   Bob (browser)
      |                      |                            |
      |-- create session --->|                            |
      |<-- join link + code--|                            |
      |                      |                            |
      |-- share link in call chat ----------------------->|
      |                      |<---- open link -------------|
      |                      |<---- proxy auth -----------|
      |                      |---- Alice identity ------->|
      |                      |<---- accept ---------------|
      |<-- Bob joined -------|                            |
      |                      |---- same code ------------>|
      |-- compare code over the call ------------------->|
      |-- confirm ---------->|                            |
      |                      |<---- confirm --------------|
      |                      |-- verify transaction ------|
      |<-- verified + receipt|---- verified + receipt --->|
```

**Detailed steps:**

1. **Create**
   - Alice opens the app. The proxy has already authenticated her.
   - She chooses “Verify someone in this call”, optionally adds context, and chooses the session duration.
   - The server creates a session with a 256-bit join token (stored as a hash) and a 2–5 minute expiry. Each participant receives a unique 6-digit + 3-word code when they create/join.
   - The response contains the join URL, QR payload, code, and expiry. The raw join token is never stored.

2. **Invite**
   - Alice shares the join link in the call chat, or shows the QR code.
   - She does not read the join token aloud. If the call has no chat, the app may show a short room code that Bob enters after logging in. The room code is convenience, not security.

3. **Join**
   - Bob opens the link. The proxy authenticates him; the BFF validates the assertions and creates/uses his BFF session.
   - The server consumes the join token (single-use) and binds Bob to the session.
   - Bob sees Alice’s identity card, assurance label, the purpose/context, what will be shared, and a warning: “Only continue if you expected this call.”

4. **Participant approval**
   - Alice sees “Bob Berg joined” with Bob’s identity and assurance label.
   - If this is not the person she expected, she cancels the session. This limits the damage of a leaked join link.

5. **Compare**
   - Each participant gets a different code: e.g., Alice sees `482 913` and Bob sees `731 044`.
   - Each code is bound to the participant’s identity and the session ID.
   - They compare it over the call. On video, they can show the screen; on voice, they read the digits and words.

6. **Confirm**
   - Each participant reads their own code aloud and enters the code they hear from the other person.
   - The server identifies the participant from the BFF session, not from the request body.
   - A successful entry is stored for that participant and the current roster version. When both directions are correct, the transaction marks the session verified.

7. **Result**
   - **Verified:** both see a success screen and a receipt.
   - **Mismatch:** either party can choose “The code/name does not match.” The session becomes `mismatch`; no receipt; both see a warning and a report link.
   - **Expired:** the session expires; no receipt; start over.

8. **Receipt**
   - The receipt contains: session reference, kind, participant display names, masked personal numbers (if available), assurance labels, timestamps, method, app version, and a disclaimer.
   - It does not contain the full personal number, the raw join token, or the verification code.
   - It is visible only to the participants (and authorized support staff with audit).

### 6.2 Customer-service flow

1. The agent creates a session from the company app.
2. The app displays the company brand, the agent’s name, and the assurance label. If the agent is authenticated by corporate SSO, the label is “Signed in via [company]”, not “legally verified”.
3. The agent sends the customer a link via SMS, email, or chat. The link is single-use and short-lived.
4. The customer opens the link and authenticates. If the customer is external, this requires a customer IdP or eID; see section 11.
5. The customer sees: “You are verifying with [Company] — agent [Name].” The company identity must be visually clear.
6. The customer confirms. The agent sees the customer’s identity and assurance label.
7. Each reads their own code aloud and enters the other person’s code.
8. The company receives an audit receipt.

**Anti-fraud copy (must appear in the customer flow):**

- “Never read this code to someone who called you.”
- “The company will never ask you to read a code to us.”
- “Only continue if you initiated this call or expected it.”
- “If the name or company does not match, stop and contact the company via its official number.”

### 6.3 In-person flow

1. Alice creates a session and shows a QR code on her phone.
2. Bob scans the QR code with his phone. The proxy authenticates him.
3. Both see each other’s identity and each gets their own code.
4. Each reads their own code aloud and enters the other person’s code.
5. The receipt is available to both.

**One-device handover:** not recommended for v1. If required, it must force a fresh authentication for the second person and clear the first person’s session; otherwise the first person’s identity can leak into the second confirmation.

### 6.4 Group flow (phase 2)

1. The host creates a group session. Options: expected participant count, or open join with a host-controlled lock.
2. Participants join via link/QR. Each participant sees the current roster.
3. The host reviews the roster and locks it. The app increments the roster version.
4. The app displays a group code and words derived from the session and the locked roster.
5. Each participant confirms the roster and the code.
6. If anyone leaves or joins after lock, the roster version increments, all confirmations are invalidated, and everyone must re-confirm.
7. The group is verified only when every required participant has confirmed the current roster version.

**What the UI must say:** “All participants who joined this app session have confirmed the same roster. This does not prove that everyone in the call joined the app.”

**Future:** call-platform integration can compare the call participant list with the app roster and flag unverified participants. That is out of scope for v1.

### 6.5 Edge cases

| Situation | Behaviour |
|---|---|
| Bob refreshes the page | His BFF session still binds him; the session reloads. The join token is already consumed; no re-use. |
| Bob opens the link on a second device | The join token is single-use. He must be re-invited, or the session must support a deliberate “add device” flow (out of scope). |
| Alice closes the tab | The session remains until expiry. Bob sees “Waiting for Alice.” If Alice does not return, it expires. |
| The same browser switches user | The proxy assertion changes; the BFF detects the subject change and invalidates the session. |
| Both confirm at the same time | The transaction serializes on the session row; only one transition to verified; one receipt. |
| One says “no match” | Session becomes `mismatch`; no receipt; the other participant sees the warning. |
| The code expires while comparing | Session becomes `expired`; start over. |
| A participant’s name changes mid-session | The server snapshots identities at join; a change in the proxy assertion for the same subject updates the snapshot only before confirmation. After confirmation, changes invalidate the session. |
| Network loss during confirmation | The client retries with an idempotency key; the server returns the same result. |
| Join link leaked and a stranger joins first | Alice sees the stranger’s identity and can cancel. For higher assurance, bind the invite to an expected identity (optional later). |
| Group roster changes after confirmations | Roster version increments; all confirmations invalidated; re-confirm. |

---

## 7. UX and screens

### 7.1 Screen list

| Screen | Purpose | Key elements |
|---|---|---|
| **Home** | Entry point | “Who are you talking to?”; Start / Join; recent receipts; safety note |
| **Create** | Configure session | Context note; duration; require eID signature (later); expected participants for group |
| **Invite** | Share the session | Large code + words; copy link; QR; “Share in the call chat”; expiry countdown; safety copy |
| **Join** | Consent and context | Initiator identity card; assurance label; what is shared; “Only continue if expected”; Continue / Cancel |
| **Verify** | The ceremony | Two identity cards; “Your code” + words; an input for the other person’s code; countdown; “Something is wrong” |
| **Waiting** | Other participant not ready | Participant status; resend link; cancel; expiry |
| **Verified** | Success | Green check; receipt; “Done”; “Download receipt” |
| **Mismatch** | Failure | Red warning; “Do not continue”; report; start over |
| **Expired** | Timeout | Explanation; start over |
| **Receipt** | Proof | Human-readable summary; JSON/PDF; signature details (later); verify link |
| **Help** | Education | What this proves; what it does not; anti-phishing guidance |

### 7.2 Visual and interaction principles

- Calm, trustworthy, not “cyber”.
- Green only after **both** participants have verified the other person’s code. Never show a green check after one direction.
- Status uses icon + text + colour, not colour alone.
- The code is large, grouped, and readable at a distance: `482 913`, with words underneath.
- Show the expiry countdown prominently.
- Show “Waiting for [name]” and “Confirmed” states clearly.
- Do not auto-confirm on page load. Confirmation must be a deliberate action.
- Keep the two directions distinct: “Your code” to read aloud, and an input for the other person’s code.
- Provide a “This is not the person” / “Something is wrong” action at every step.
- Show name and masked number by default, e.g. `1990••••-••••`. A participant may reveal their own full number explicitly; never disclose someone else’s without that action.
- Show the assurance label next to the name. Do not use a generic “Verified” badge without saying what was verified.
- Anti-phishing copy must be visible, not buried in help.

### 7.3 Accessibility

- WCAG 2.2 AA target.
- Keyboard navigation for all actions.
- Screen-reader labels for the code, words, status, and countdown.
- Do not rely on colour alone.
- Large touch targets; mobile-first layout.
- Support text zoom and high contrast.
- Avoid motion that cannot be reduced.
- The code must be readable by a screen reader as grouped digits and words.
- Test with VoiceOver/TalkBack and at least one desktop screen reader.

### 7.4 Localization

- Swedish first; English secondary if needed.
- Code words must be localized and curated: no offensive words, no homophones that are easily confused, no words that are hard to spell.
- Digits are language-neutral but can be misheard; words reduce errors. Use both.
- Test the code aloud with native speakers.

### 7.5 Mobile / PWA

- Responsive web app; installable PWA optional.
- Camera access only for QR scanning; request it at the moment of use; explain why.
- BankID/Freja app switching (later phase) must preserve session state.
- Screen wake lock while showing the code, if supported.
- Do not rely on push notifications for the core flow; they are optional.

---

## 8. Architecture

### 8.1 Components

| Component | Responsibility |
|---|---|
| **Auth proxy / IdP** (existing) | Authenticates users; injects identity assertions; strips client-supplied identity headers; enforces access to the app network |
| **BFF / web app** | Validates assertions; creates BFF sessions; renders pages; enforces authorization; orchestrates verification; serves JSON for polling |
| **Verification domain module** | Session state machine, code generation, roster management, confirmation logic, receipts |
| **SQLite (v0.2)** | System of record: users, sessions, participants, events, receipts |
| **Postgres / Redis** (future) | Horizontal scaling, shared rate limits, pub/sub |
| **Expiry worker** | Marks expired sessions; emits events; cleans up ephemeral data |
| **eID adapter** (future) | BankID/Freja auth and signature integration behind a common interface |
| **Audit/receipt service** | Append-only events; receipt generation; integrity protection |
| **Observability** | Metrics, logs, traces, alerts; PII redaction |

### 8.2 Why a BFF

- The browser never sees the identity headers. It receives only the session view, which may include the full personal number when the product requirement/config allows it.
- The BFF creates its own `HttpOnly` session cookie; the browser sends only that cookie.
- Authorization and CSRF are enforced server-side.
- Future SSE/WebSocket connections can be authenticated with the same session; v0.2 uses short polling.
- The app can rotate/revoke sessions independently of the proxy.
- The proxy can be replaced without rewriting the frontend.

### 8.3 Implemented stack (v0.2)

The environment did not have Node.js, and the app is deliberately small. The implementation uses:

- **Language:** Python 3.14.
- **HTTP:** standard-library `ThreadingHTTPServer` with a small router.
- **Templates:** Jinja2, server-rendered pages plus a small amount of vanilla JS.
- **Database:** SQLite (WAL) for v0.2.
- **Validation:** explicit Python validators at every boundary.
- **UI:** plain CSS design system inspired by apps.bergling.net; no external fonts or requests.
- **Realtime:** 1.4-second polling. SSE/WebSocket is a future improvement.
- **Rate limiting:** in-process limiter; replace with Redis for multiple instances.
- **Tests:** Python `unittest` + real HTTP requests against an ephemeral server.
- **Dev environment:** Docker Compose with the app and a mock/dev identity mode.
- **Production:** EU region; TLS; persistent volume for SQLite; secrets manager; WAF; backups; structured logs with PII redaction.

**Scaling:** SQLite is a single-writer database. For horizontal scaling, move to PostgreSQL, use Redis for shared rate limits and pub/sub, and consider SSE/WebSocket for push updates. The domain model (sessions, participants, events, receipts) maps directly.

**Why not Next.js/TypeScript:** the prototype needed to run in the available environment without a Node toolchain. The HTTP boundary and domain model are framework-agnostic; a future port is straightforward.

### 8.4 Deployment shape

```
Internet
  │
  ▼
TLS / WAF / DDoS protection
  │
  ▼
Auth proxy / IdP  ──> identity headers / JWT
  │
  ▼ (private network / mTLS)
BFF / app  ──> SQLite (v0.2)
  │        └─> Postgres/Redis (future)
  │
  └─> eID provider (future, mTLS)
```

- The app must not be reachable from the internet except through the proxy.
- The database must not be reachable from the browser.
- Egress to the eID provider should be restricted and monitored.
- Secrets (session keys, HMAC pepper, DB credentials, eID client certificates) live in a secret manager, not in the repo or images.

### 8.5 Multi-instance behaviour

- Session state is in Postgres, not in process memory.
- SSE fan-out uses Redis pub/sub (or a managed equivalent) when there is more than one instance.
- Sticky sessions are not required.
- Expiry is enforced by a worker and by lazy checks on read.
- Rate limits must be shared across instances (Redis).

---

## 9. Data model

The following is a logical schema. Column types and indexes are indicative.

### 9.1 `users`

| Column | Type | Notes |
|---|---|---|
| `id` | uuid PK | Internal ID. |
| `subject` | text unique not null | `x-userid`. Stable, opaque. |
| `idp` | text not null | Issuer/proxy identifier. |
| `display_name` | text not null | Derived from `x-name` + `x-lastname`; escaped on output. |
| `given_name` | text | |
| `family_name` | text | |
| `proxy_name` | text | Name as asserted by the proxy; may be a directory name. |
| `verified_name` | text null | Name from BankID/Freja, if later step-up. |
| `pn_hmac` | bytea null | HMAC-SHA256(pepper, normalized personal number). Never raw. |
| `pn_masked` | text null | e.g. `1990••••-••••`. |
| `assurance` | text not null | `proxy`, `eid_auth`, `eid_sign`. |
| `created_at` | timestamptz | |
| `updated_at` | timestamptz | |

**Rules:**

- Upsert on `subject` at first sight.
- Do not overwrite `verified_name` with a weaker proxy name.
- If `x-userid` is the personal number, HMAC it at ingress and use the HMAC as `subject`; never store the raw value.
- Names are untrusted input even when they come from the IdP. Escape them; normalize Unicode; limit length.

### 9.2 `verification_sessions`

| Column | Type | Notes |
|---|---|---|
| `id` | uuid PK | Internal ID. |
| `public_ref` | text unique | Human-readable reference, e.g. `VS-7F3K2`. |
| `kind` | text | `one_to_one`, `customer_service`, `in_person`, `group`. |
| `state` | text | State machine value. |
| `initiator_id` | uuid FK users | |
| `context_note` | text null | Optional user-provided context; treat as sensitive. |
| `require_eid_sign` | boolean | Later phase. |
| `join_token_hash` | bytea not null | SHA-256 of the raw token. Raw token never stored. |
| `participant.code` / `participant.words` | text | Each participant’s own code and words, generated at create/join. The API returns only the current participant’s code. |
| `code_words` | text | Localized words. |
| `roster_version` | int not null default 0 | Incremented on participant set changes. |
| `expected_participants` | int null | For group sessions. |
| `expires_at` | timestamptz not null | |
| `created_at` | timestamptz | |
| `completed_at` | timestamptz null | |
| `version` | int not null default 0 | Optimistic concurrency. |

**Indexes:** `(state, expires_at)`, `(initiator_id, created_at)`, `public_ref`.

### 9.3 `participants`

| Column | Type | Notes |
|---|---|---|
| `id` | uuid PK | |
| `session_id` | uuid FK | |
| `user_id` | uuid FK | |
| `role` | text | `initiator`, `responder`, `host`, `member`. |
| `joined_at` | timestamptz | |
| `confirmed_at` | timestamptz null | |
| `decision` | text null | `match`, `no_match`. |
| `confirmed_roster_version` | int null | Confirmation is bound to the roster version. |
| `assurance` | text | Snapshot at join/confirm. |
| `left_at` | timestamptz null | |

**Constraint:** unique `(session_id, user_id)`.
**Indexes:** `(session_id)`, `(user_id, joined_at)`.

### 9.4 `session_events`

| Column | Type | Notes |
|---|---|---|
| `id` | bigserial PK | |
| `session_id` | uuid FK | |
| `actor_id` | uuid null | Null for system events. |
| `type` | text | `created`, `joined`, `locked`, `confirmed`, `verified`, `mismatch`, `expired`, `cancelled`, etc. |
| `data` | jsonb | Minimal, redacted. No codes, tokens, or full PN. |
| `created_at` | timestamptz | |
| `ip_hash` | bytea null | Hashed, not raw. |
| `ua_hash` | bytea null | Hashed, not raw. |

Append-only. The application role should have `INSERT` and `SELECT`, not `UPDATE`/`DELETE` (except retention jobs with a separate role).

### 9.5 `attestations` (later phase)

| Column | Type | Notes |
|---|---|---|
| `id` | uuid PK | |
| `session_id` | uuid FK | |
| `user_id` | uuid FK | |
| `provider` | text | `bankid`, `freja`, etc. |
| `payload_hash` | bytea | Hash of the canonical signed statement. |
| `signature` | bytea | Raw signature. |
| `certificate_chain` | jsonb | Validation evidence. |
| `signed_at` | timestamptz | |
| `verification_result` | jsonb | OCSP/CRL, issuer, etc. |

### 9.6 `receipts`

| Column | Type | Notes |
|---|---|---|
| `id` | uuid PK | |
| `session_id` | uuid unique FK | One receipt per verified session. |
| `payload` | jsonb | Redacted receipt data. |
| `pdf` | bytea null | Generated PDF. |
| `created_at` | timestamptz | |
| `integrity_hmac` | bytea | Server-side HMAC over the payload, or a signature. |

### 9.7 `idempotency_keys`

For POST endpoints that can be retried:

| Column | Type | Notes |
|---|---|---|
| `key` | text PK | Client-provided idempotency key. |
| `user_id` | uuid | |
| `request_hash` | bytea | Reject key reuse with a different body. |
| `response` | jsonb | Cached response. |
| `created_at` | timestamptz | TTL cleanup. |

### 9.8 Personal data rules

- **Do not store the raw personal number in plaintext.** v0.2 stores it with Fernet encryption at rest (key derived from `SECRET_KEY` or a separate `PN_ENCRYPTION_KEY`).
- If matching across sessions is needed, store `HMAC-SHA256(pepper, normalized_pn)` instead of ciphertext. A plain hash is not enough; the personal-number space is small.
- The full number may be displayed **in-session** when `pn_mode='full'`, or after a participant explicitly reveals their own number in masked mode. Hide it when the tab loses visibility.
- Mask the personal number in all receipts: `1990••••-••••`.
- Do not put the personal number in URLs, QR codes, logs, analytics, error messages, or receipts.
- Treat `context_note` as potentially sensitive: users may type personal or financial details. Limit length, escape it, and include it in retention/deletion.
- Receipts contain names and masked identifiers; protect them with authorization, not just an unguessable URL.
- A DPIA and legal review are required before production use of full personal-number display.

---

## 10. State machine and consistency

### 10.1 States

```
created ──> waiting ──> ready ──> confirming ──> verified
   │           │           │            │
   │           │           │            ├──> mismatch
   │           │           │            └──> expired
   │           │           └──> cancelled
   │           └──> expired
   └──> cancelled
```

| State | Meaning |
|---|---|
| `created` | Session row created; invite not yet shared. |
| `waiting` | Waiting for enough participants to join. |
| `ready` | Required participants have joined; host has locked the roster (group) or both are present (1:1). |
| `confirming` | At least one participant has confirmed; waiting for the rest. |
| `verified` | All required participants confirmed the same roster version. Terminal. |
| `mismatch` | At least one participant reported a mismatch. Terminal; no receipt. |
| `expired` | TTL elapsed before verification. Terminal. |
| `cancelled` | A participant/host cancelled. Terminal. |

### 10.2 Transition rules

1. `created → waiting` on creation.
2. `waiting → ready` when the required participant set is present:
   - 1:1/customer service: exactly two participants.
   - in-person: exactly two participants.
   - group: host locks the roster (or expected count is reached and auto-lock is enabled).
3. `ready → confirming` on the first `match` confirmation.
4. `confirming → verified` when every required participant has `decision = match` and `confirmed_roster_version = current roster_version`.
5. Any `no_match` → `mismatch` immediately.
6. `waiting/ready/confirming → cancelled` on cancel.
7. `waiting/ready/confirming → expired` when `now >= expires_at`.
8. Roster changes after `ready`:
   - If a participant leaves or is added, increment `roster_version`.
   - Clear all `confirmed_at`, `decision`, and `confirmed_roster_version`.
   - Return to `ready` (or `waiting` if below the required count).
   - Emit a `roster.changed` event; clients show “The participant list changed. Please confirm again.”
9. `verified`, `mismatch`, `expired`, `cancelled` are terminal. A new verification requires a new session.

### 10.3 Confirmation transaction

The second confirmation must be processed in a single transaction with row locking:

```
BEGIN;
SELECT * FROM verification_sessions WHERE id = $1 FOR UPDATE;
-- check state, expiry, roster_version, participant membership
-- upsert participant confirmation (decision, confirmed_at, roster_version)
-- if any participant has decision = no_match -> mismatch
-- if all required participants have match at current roster_version -> verified
-- create receipt exactly once (unique session_id)
COMMIT;
```

- The participant identity comes from the BFF session, never from the request body.
- The confirmation must include the `roster_version` the user saw. If it is stale, reject with `409 Conflict` and show the updated roster.
- Use an idempotency key so retries do not create duplicate receipts.
- Use a unique constraint on `receipts.session_id` to prevent double receipts.
- The confirmation request contains the code the participant heard from the other person. The server compares it with the other participant’s code; it never returns the other participant’s code to the client.

### 10.4 Expiry

- Lazy: every read checks `expires_at`; if expired, transition to `expired`.
- Worker: a background job every 30–60 seconds expires stale sessions and emits events.
- Clients show a countdown based on server time; do not trust the client clock.
- When expired, clear ephemeral code material and invalidate the join token.

### 10.5 Concurrency

- `version` column for optimistic concurrency.
- `SELECT ... FOR UPDATE` for the confirmation transaction.
- Unique `(session_id, user_id)` on participants.
- Unique `receipts.session_id`.
- Idempotency keys on create/join/confirm/cancel.
- Rate limits in Redis (shared across instances).

---

## 11. API

All endpoints are served by the BFF and require a valid BFF session unless stated otherwise. State-changing requests require CSRF protection.

### 11.1 Endpoints

| Method | Path | Purpose | Auth |
|---|---|---|---|
| `POST` | `/api/sessions` | Create a session | BFF session + CSRF |
| `GET` | `/api/sessions/:id` | Get session state for a participant | Participant only |
| `POST` | `/api/sessions/:id/join` | Join with a join token | BFF session + join token + CSRF |
| `POST` | `/api/sessions/:id/lock` | Lock a group roster (host) | Host only + CSRF |
| `POST` | `/api/sessions/:id/confirm` | Confirm match/no-match | Participant only + CSRF |
| `POST` | `/api/sessions/:id/leave` | Leave a session | Participant only + CSRF |
| `POST` | `/api/sessions/:id/cancel` | Cancel a session | Initiator/host only + CSRF |
| `GET` | `/api/sessions/:id/events` | SSE stream of state changes | Participant only |
| `GET` | `/api/receipts/:id` | Get a receipt | Participant only |
| `POST` | `/api/sessions/:id/step-up` | Start eID step-up (later) | Participant only + CSRF |
| `GET` | `/healthz` | Liveness/readiness | Internal network only |

### 11.2 Create request/response

```http
POST /api/sessions
Content-Type: application/json
Idempotency-Key: 5b2e...

{
  "kind": "one_to_one",
  "context": "Apartment viewing",
  "requireEidSign": false
}
```

```json
{
  "id": "9f0c...",
  "publicRef": "VS-7F3K2",
  "joinUrl": "https://app.example/v/3f9c...",
  "code": "482 913",
  "words": ["katt", "berg", "cykel"],
  "expiresAt": "2026-11-18T22:04:00Z"
}
```

- The join URL contains a high-entropy token. It is returned once; the server stores only its hash.
- The code is returned to the creator and to the joiner; it is not stored in logs.
- The raw join token must not be embedded in analytics or referrer headers.

### 11.3 Confirm request

```http
POST /api/sessions/9f0c.../confirm
Content-Type: application/json
Idempotency-Key: a71c...

{
  "decision": "match",
  "rosterVersion": 1
}
```

- No `userId` in the body. The server uses the BFF session.
- If `rosterVersion` is stale, return `409` with the current roster.
- If the session is expired/terminal, return `409` with the current state.

### 11.4 Error model

```json
{
  "error": {
    "code": "session_expired",
    "message": "This verification has expired. Start a new one.",
    "requestId": "..."
  }
}
```

- No stack traces, SQL errors, personal data, or internal IDs in error responses.
- Use stable machine-readable codes for the UI.
- Rate-limit responses use `429` with `Retry-After`.

### 11.5 SSE events

```
event: session.updated
data: {"state":"confirming","rosterVersion":1,"participants":[...]}

event: participant.confirmed
data: {"userId":"...","displayName":"Bob Berg","decision":"match"}

event: session.verified
data: {"receiptId":"..."}

event: session.mismatch
data: {"reason":"code_or_identity"}

event: session.expired
data: {}
```

- SSE connections require a valid BFF session and participant authorization.
- Validate `Origin`; do not put tokens in query strings.
- Send heartbeats; handle reconnect with `Last-Event-ID` or a full state refresh.

### 11.6 Rate limits

| Action | Limit (initial proposal) |
|---|---|
| Create session | 10 per user per hour; 30 per IP per hour |
| Join attempt | 20 per user per hour; 60 per IP per hour |
| Confirm | 30 per user per minute |
| Code entry (if used) | 5 per minute per session, then lock |
| SSE connect | 10 per user per minute |
| Receipt download | 30 per user per hour |

Tune after load testing. Use Redis so limits are shared across instances.

---

## 12. Security controls

The detailed threat analysis is in [threat-model.md](threat-model.md). This section is the implementation checklist.

### 12.1 Identity boundary

- [ ] The app is reachable only through the proxy (network policy/firewall/mTLS).
- [ ] The proxy strips all client-supplied identity headers.
- [ ] The proxy-to-app connection is authenticated (mTLS or private network).
- [ ] Identity assertions are signed or protected by mTLS; validate issuer, audience, expiry.
- [ ] Reject duplicate, empty, overlong, or malformed headers.
- [ ] Fail closed on missing/invalid identity.
- [ ] Never accept a user ID from the browser.
- [ ] Detect `x-userid` changes within a BFF session and invalidate it.

### 12.2 Session security

- [ ] `__Host-` cookie prefix; `Secure`; `HttpOnly`; `SameSite=Lax` or `Strict`; `Path=/`.
- [ ] Rotate the session ID on login.
- [ ] Idle and absolute timeouts.
- [ ] Logout clears the BFF session and redirects to proxy logout.
- [ ] Bind the BFF session to the proxy subject.
- [ ] Re-authenticate before eID signing (later).

### 12.3 Web security

- [ ] CSRF token on all state-changing requests; `Origin`/`Referer` checks.
- [ ] CSP: `default-src 'self'`; `frame-ancestors 'none'`; `base-uri 'none'`; `form-action 'self'`; no third-party scripts unless reviewed.
- [ ] Escape all names and context notes; never use raw HTML injection.
- [ ] `X-Content-Type-Options: nosniff`; `Referrer-Policy: no-referrer`; HSTS.
- [ ] Clickjacking protection.
- [ ] No PII in URLs, analytics, or error reporting.
- [ ] Dependency lockfile, SCA, secret scanning, SBOM, container scanning.
- [ ] WAF/DDoS protection at the edge.

### 12.4 Verification-specific controls

- [ ] Join token: 256-bit random, single-use, hashed at rest, short TTL.
- [ ] Verification code: unique per participant, CSPRNG, 6 digits + 3 words, short TTL, one-time, bound to participant + session + roster version.
- [ ] A participant never receives the other participant’s code from the API.
- [ ] The code is **not** used to join or authenticate.
- [ ] Both participants must successfully enter the other person’s code; one-sided verification never verifies.
- [ ] Confirmations are bound to the roster version; roster changes invalidate them.
- [ ] The server identifies the participant from the BFF session.
- [ ] Receipt creation is unique and transactional.
- [ ] Receipt has an integrity HMAC/signature; access is authorized.
- [ ] Expiry is enforced server-side.

### 12.5 Audit and monitoring

- [ ] Append-only session events.
- [ ] Audit: who verified whom, when, method, assurance, result.
- [ ] Alert on abnormal patterns: many failed joins, many created sessions, repeated mismatches, header anomalies.
- [ ] Redact tokens, codes, cookies, and personal numbers from logs.
- [ ] Retain audit logs per policy; restrict access.

### 12.6 Testing requirements

- [ ] Forged identity headers from outside the proxy are rejected.
- [ ] Direct access to the app bypassing the proxy is impossible.
- [ ] Duplicate/oversized/malformed headers are rejected.
- [ ] IDOR: Alice cannot read/modify Bob’s session or receipt.
- [ ] CSRF: cross-site POST fails.
- [ ] XSS: a name containing `<script>` is escaped.
- [ ] Race: two simultaneous confirmations produce exactly one verified state and one receipt.
- [ ] Replay: a used join token cannot be reused.
- [ ] Expiry: an expired session cannot be confirmed.
- [ ] Rate limits work across instances.
- [ ] SSE requires authorization.
- [ ] No personal number/code/token in logs.
- [ ] Receipt access is participant-only.
- [ ] Malformed/unknown state transitions are rejected.

---

## 13. Privacy and compliance

### 13.1 Roles

- The app operator may be the **data controller** for consumer data, or a **processor** for an organization’s employee/customer data.
- The proxy/IdP and eID providers are separate controllers/processors with their own terms.
- Clarify the role before launch; it determines the privacy notice, DPA, and retention.

### 13.2 Lawful basis

- Likely legitimate interest (fraud prevention, secure customer interactions) or contract performance.
- If optional data is shared with the other party, consider consent or explicit transparency.
- Document the assessment. Do not rely on “the user logged in” as a lawful basis for everything.

### 13.3 Data minimization

- Do not collect the full personal number unless legally required. The core flow does not need it.
- Do not collect call audio/video, transcripts, or content.
- `context_note` is optional; warn users not to enter sensitive information.
- Receipts contain only what is needed: names, masked identifiers, assurance, timestamps.
- Do not use third-party analytics that receive identifiers or page content.

### 13.4 DPIA

A DPIA is likely required because the app processes identity data and may process personal numbers at scale. Include:

- purpose and necessity,
- data flows and processors,
- retention,
- access controls,
- risks to data subjects,
- mitigations,
- residual risk,
- sign-off.

### 13.5 Retention

Proposed defaults, to be confirmed:

| Data | Retention |
|---|---|
| Active session state | Until expiry + 24 hours |
| Session events | 90 days |
| Receipts | 1 year (or per customer contract) |
| Audit/security logs | 1 year |
| Rate-limit counters | 24 hours |
| Deleted user data | Per DSAR process; legal hold exception |

Make retention configurable per tenant if the product becomes multi-tenant.

### 13.6 Data subject rights

- Access: participants can view their sessions/receipts.
- Rectification: names come from the IdP; correct at the source.
- Erasure: delete session data/receipts unless a legal obligation requires retention.
- Restriction/objection: process according to the applicable lawful basis.
- Portability: export receipts as JSON/PDF.

### 13.7 Processors and transfers

- Hosting in the EU.
- DPAs with the hosting provider, proxy/IdP operator, and eID provider.
- If any data leaves the EU/EEA, document the transfer mechanism.
- BankID/Freja contracts may impose additional requirements.

### 13.8 Accessibility and consumer protection

- WCAG 2.2 AA.
- Clear, non-deceptive copy. Do not claim “verified voice” or “secure call” unless true.
- Allow users to decline; do not make verification mandatory where it is not legally required.
- Provide a human alternative for accessibility or failure cases.

### 13.9 Legal review

- Terms of service and privacy notice.
- eIDAS assessment if signatures are introduced.
- BankID/Freja branding and contract terms.
- Consumer protection and distance-contract rules if used for sales.
- Records retention and evidence rules if receipts are used in disputes.

---

## 14. BankID and Freja

They solve **authentication** (and optionally signing). They do not, by themselves, implement mutual verification between two people. The app still needs the ceremony, session binding, and receipt.

| | **BankID** | **Freja eID+** |
|---|---|---|
| Coverage | Sweden only (Norwegian BankID is separate) | Sweden-centric; some international coverage; Plus level is Sweden-only |
| Assurance | High; Swedish personal number | Basic / Extended / Plus |
| Authentication | Yes, RP API v6 | Yes, OpenID Connect |
| Signing | Yes, `/sign` | Yes, Freja Signature API; **not** via OIDC |
| Integration | mTLS client certificate, animated QR, `/auth`, `/sign`, `/collect` | OIDC for auth; REST + client certificate for signing |
| Production | Agreement via bank or broker; certificate; branding | Contract; client certificate; branding |
| Best for | Swedish users, high-assurance verification | Swedish alternative; some non-Swedish users |

### 14.1 Recommendation

1. **v1:** use the existing proxy. Do not integrate a second eID unless the proxy’s assurance is insufficient. Add an assurance claim to the proxy if possible.
2. **If the proxy is already BankID/Freja-based:** use its assertion and label it correctly. Do not re-authenticate unnecessarily.
3. **If external customers need authentication and the proxy is employee-only:** plan a customer IdP or eID. BankID via a broker is the fastest Swedish route; Freja is an alternative; international users need another provider/eIDAS.
4. **If high assurance is required:** add an eID step-up at confirmation time and optional signing. Use an adapter interface so BankID/Freja/other providers can be swapped.
5. **Do not overclaim:** BankID authentication is not the same as a qualified signature. For qualified signatures, use a QTSP.

### 14.2 Integration notes (future)

- Keep all eID client certificates and private keys server-side; never in the browser.
- Validate signatures, certificate chains, and OCSP/CRL.
- Use the provider’s test environment first.
- Bind the eID order to the verification session and a nonce; prevent replay.
- Show the exact statement being signed; include both identities, session reference, purpose, and timestamp.
- Handle cancellation, timeout, already-in-progress, and provider outages gracefully.
- Budget for contracts, per-transaction fees, and onboarding time.

---

## 15. Naming

The product name is **Verify**, renamed from the earlier working name **Samsyn** on 2026-11-21. Samsyn was dropped because of prior use in the same space (IKEA Samsyn, Sambruk’s Samsyn, Samsyn AB, samsyn.io). “Verify” is a common word, so trademark and domain clearance is still required before commercial branding. See [naming.md](naming.md).

Do not use “BankID” or “Freja” in the product name. Do not imply affiliation.

---

## 16. Phasing and delivery plan

### Phase 0 — Design and prototype

- Review this document and the threat model.
- Resolve the open questions (section 18).
- Build a clickable prototype with:
  - a mock proxy/IdP that injects headers,
  - two browser windows (Alice/Bob),
  - create/join/compare/confirm/receipt,
  - mismatch, expiry, and refresh states.
- Test the ceremony with 5–10 real users. Measure whether they actually read their own code and enter the other person’s code.

**Deliverables:** prototype, UX copy, test plan, updated design.

### Phase 1 — MVP

- 1:1 remote + in-person.
- Existing proxy integration; BFF session; header validation.
- Session state machine; join token; per-person verification codes; mutual code verification.
- Receipts and audit events.
- Rate limits, CSRF, CSP, session security.
- Deployment in the EU; monitoring; backups.
- Security tests, including forged headers and IDOR.

**Out of scope:** eID, group, call-platform integration, legal signatures.

### Phase 2 — Customer service and group

- Customer-service variant, if external customer authentication is available.
- Group sessions with roster lock, group code, roster versioning, and re-confirmation.
- Admin/support tooling with least privilege.
- Retention configuration and DSAR tooling.

### Phase 3 — Higher assurance

- eID step-up (BankID/Freja) behind an adapter.
- Optional signing and receipt verification.
- Call-platform integration to bind the app session to the meeting/participant list.
- International eID/eIDAS if needed.

### Phase 4 — Optional

- Qualified signatures/QTSP.
- Organization branding/multi-tenancy.
- Analytics for fraud patterns (privacy-preserving).
- Native mobile app, if the PWA is insufficient.

---

## 17. Acceptance criteria

### 17.1 Functional

- [ ] Alice can create a session and share a join link/QR.
- [ ] Bob can join, authenticate, and see Alice’s identity and assurance.
- [ ] Each participant sees only their own code and words.
- [ ] Each participant must enter the other participant’s code before the session becomes verified.
- [ ] One-sided confirmation never produces a receipt.
- [ ] A mismatch produces no receipt and warns both parties.
- [ ] An expired session cannot be confirmed.
- [ ] Refreshing the page preserves the participant’s session.
- [ ] A leaked/used join token cannot be reused.
- [ ] Group roster changes invalidate prior confirmations (phase 2).
- [ ] Receipts are downloadable and participant-only.

### 17.2 Security

- [ ] Forged identity headers from outside the proxy fail.
- [ ] Direct app access bypassing the proxy fails.
- [ ] Duplicate/malformed headers fail closed.
- [ ] IDOR tests fail (no cross-user access).
- [ ] CSRF tests fail.
- [ ] XSS in names/context is escaped.
- [ ] Race tests produce one verified state and one receipt.
- [ ] Expiry and replay tests pass.
- [ ] Rate limits work across instances.
- [ ] SSE requires authorization.
- [ ] No personal number, code, or token appears in logs.
- [ ] Receipt integrity is verifiable.

### 17.3 Privacy

- [ ] Full personal numbers are encrypted at rest, never logged, and never written to receipts; in-session display follows `pn_mode` or explicit reveal.
- [ ] Retention jobs delete expired data.
- [ ] Receipts are visible only to participants and authorized support.
- [ ] Privacy notice and DPIA are in place.
- [ ] Context notes are optional and escaped.

### 17.4 Operations

- [ ] Health checks and metrics.
- [ ] Alerts for error rate, latency, failed joins, header anomalies.
- [ ] Backup and restore tested.
- [ ] Migration process documented.
- [ ] Incident response runbook.
- [ ] Kill switch to disable verification.

---

## 18. Open questions

These must be answered before or during phase 0. If an answer is unknown, we will propose a default and mark it as a decision.

### 18.1 Identity and proxy

1. Which proxy/IdP product is in front of the app?
2. Does it sign the identity assertion, or is it bare headers over a private network?
3. Does it strip client-supplied identity headers? Can you prove it with a test?
4. Is the app reachable only through the proxy? Any direct ports, WebSocket endpoints, or health endpoints?
5. What assurance does the proxy actually provide? Is it BankID/Freja, a corporate directory, or a custom login?
6. Can the proxy add `x-auth-issuer` and `x-auth-assurance`? Can it provide a JWT instead of bare headers?
7. Is `x-userid` stable and opaque? Is `x-name` the given name?
8. What exactly is `x-personid`? Swedish personnummer? Is it required anywhere, or can we use an HMAC/mask only?

### 18.2 Users and scenarios

9. **Resolved:** the proxy authenticates both employees and external customers.
10. What is the proxy’s actual assurance for customers, and can it set `X-Auth-Assurance`?
11. Is the product consumer-facing, B2B, or both?
12. Is it multi-tenant (multiple companies with their own branding)?
13. Group calls: how many participants? Is the app roster enough, or do you need the call participant list?
14. Which call platforms are used: Teams, Zoom, Google Meet, phone, something else? Do you have API access?
15. **Resolved:** in-person is in scope for v0.2.

### 18.3 Product and operations

16. What is the consequence of a false verification? Fraud, money, health, legal, reputation?
17. Are receipts used as evidence? If so, for how long, and do they need signatures?
18. What retention periods are required?
19. Swedish only, or Swedish + English?
20. Any accessibility or consumer-protection requirements?
21. Stack/hosting preference: cloud, on-prem, EU-only?
22. Budget/timeline for eID contracts and certificates?
23. Who operates support and incident response?
24. **Resolved:** renamed to Verify on 2026-11-21; commercial use still requires trademark/domain clearance. See [naming.md](naming.md).

---

## 19. Glossary

- **BFF** — Backend for Frontend. A server-side layer that holds the session and talks to internal services.
- **CSRF** — Cross-Site Request Forgery.
- **CSP** — Content Security Policy.
- **DPIA** — Data Protection Impact Assessment.
- **eID** — Electronic identification (BankID, Freja, etc.).
- **eIDAS** — EU regulation for electronic identification and trust services.
- **HMAC** — Hash-based Message Authentication Code; a keyed hash.
- **IDOR** — Insecure Direct Object Reference; accessing another user’s resource by changing an ID.
- **JWS** — JSON Web Signature.
- **PII** — Personally identifiable information.
- **QTSP** — Qualified Trust Service Provider.
- **SAS** — Short Authentication String; a human-comparable code.
- **SSE** — Server-Sent Events.
- **SSO** — Single Sign-On.
- **STRIDE** — Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege.
