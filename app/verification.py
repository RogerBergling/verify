from __future__ import annotations

import json
import sqlite3
from datetime import timedelta
from typing import Any

from . import auth, db, security
from .config import Config


class VerificationError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


TERMINAL = {"verified", "mismatch", "expired", "cancelled"}
REQUIRED_PARTICIPANTS = 2


def _fetch(conn: sqlite3.Connection, verification_id: str) -> dict[str, Any] | None:
    return db.row_to_dict(
        conn.execute("SELECT * FROM verifications WHERE id = ?", (verification_id,)).fetchone()
    )


def _participants(conn: sqlite3.Connection, verification_id: str) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in conn.execute(
            "SELECT * FROM participants WHERE verification_id = ? ORDER BY joined_at, id",
            (verification_id,),
        ).fetchall()
    ]


def _unique_public_ref(conn: sqlite3.Connection) -> str:
    for _ in range(12):
        ref = security.new_public_ref()
        if not conn.execute(
            "SELECT 1 FROM verifications WHERE public_ref = ?", (ref,)
        ).fetchone():
            return ref
    raise VerificationError(500, "reference_error", "Could not allocate a session reference")


def create_verification(
    config: Config,
    auth_ctx: auth.AuthContext,
    *,
    kind: str,
    context: str,
    pn_mode: str,
    duration_minutes: int,
    ip_hash: str | None = None,
    ua_hash: str | None = None,
) -> tuple[str, str]:
    try:
        kind = security.validate_kind(kind)
        pn_mode = security.validate_pn_mode(pn_mode)
        context = security.validate_context(context)
    except ValueError as exc:
        raise VerificationError(400, "invalid_input", str(exc)) from exc

    duration_minutes = max(2, min(int(duration_minutes or 10), 15))
    now = security.utcnow()
    token = security.new_token()
    verification_id = security.new_id()
    conn = db.connect(config)
    try:
        reference = _unique_public_ref(conn)
        words = security.new_words()
        conn.execute(
            """
            INSERT INTO verifications
                (id, public_ref, kind, state, initiator_id, context, pn_mode,
                 join_token_hash, join_token_enc, code, words, roster_version,
                 expires_at, created_at, version)
            VALUES (?, ?, ?, 'waiting', ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 0)
            """,
            (
                verification_id,
                reference,
                kind,
                auth_ctx.user["id"],
                context,
                pn_mode,
                security.token_hash(token),
                security.encrypt_value(
                    config.secret_key, config.pn_encryption_key, token
                ),
                security.new_code(),
                json.dumps(words, ensure_ascii=False),
                security.iso(now + timedelta(minutes=duration_minutes)),
                security.iso(now),
            ),
        )
        _insert_participant(
            conn,
            config,
            verification_id,
            auth_ctx,
            role="initiator",
            joined_at=security.iso(now),
        )
        db.audit(
            conn,
            verification_id=verification_id,
            actor_id=auth_ctx.user["id"],
            event_type="created",
            data={"kind": kind, "pn_mode": pn_mode},
            ip_hash=ip_hash,
            ua_hash=ua_hash,
        )
        conn.commit()
        return verification_id, token
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _unique_participant_code(conn: sqlite3.Connection, verification_id: str) -> str:
    for _ in range(25):
        code = security.new_code()
        existing = conn.execute(
            "SELECT 1 FROM participants WHERE verification_id = ? AND code = ?",
            (verification_id, code),
        ).fetchone()
        if not existing:
            return code
    raise VerificationError(500, "code_error", "Could not allocate a unique code")


def _insert_participant(
    conn: sqlite3.Connection,
    config: Config,
    verification_id: str,
    auth_ctx: auth.AuthContext,
    *,
    role: str,
    joined_at: str,
) -> None:
    identity = auth_ctx.identity
    conn.execute(
        """
        INSERT INTO participants
            (id, verification_id, user_id, role, subject, first_name, last_name,
             display_name, assurance, org, pn_encrypted, pn_masked,
             code, words, joined_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            security.new_id(),
            verification_id,
            auth_ctx.user["id"],
            role,
            identity.subject,
            identity.first_name,
            identity.last_name,
            identity.display_name,
            identity.assurance,
            identity.org,
            security.encrypt_pn(
                config.secret_key, config.pn_encryption_key, identity.person_id
            ),
            security.mask_pn(identity.person_id) if identity.person_id else None,
            _unique_participant_code(conn, verification_id),
            json.dumps(security.new_words(), ensure_ascii=False),
            joined_at,
        ),
    )


def _refresh(
    conn: sqlite3.Connection,
    config: Config,
    verification: dict[str, Any],
    *,
    commit: bool = True,
) -> dict[str, Any]:
    if verification["state"] in TERMINAL:
        return verification

    now = security.iso()
    participants = _participants(conn, verification["id"])

    if verification["expires_at"] <= now:
        conn.execute(
            "UPDATE verifications SET state = 'expired', version = version + 1 WHERE id = ?",
            (verification["id"],),
        )
        db.audit(
            conn,
            verification_id=verification["id"],
            actor_id=None,
            event_type="expired",
        )
        verification["state"] = "expired"
        verification["version"] += 1
        if commit:
            conn.commit()
        return verification

    if any(p["decision"] == "no_match" for p in participants):
        if verification["state"] != "mismatch":
            conn.execute(
                "UPDATE verifications SET state = 'mismatch', version = version + 1 WHERE id = ?",
                (verification["id"],),
            )
            db.audit(
                conn,
                verification_id=verification["id"],
                actor_id=None,
                event_type="mismatch",
            )
            verification["state"] = "mismatch"
            verification["version"] += 1
        if commit:
            conn.commit()
        return verification

    current_confirmations = [
        p
        for p in participants
        if p["decision"] == "match"
        and p["confirmed_roster_version"] == verification["roster_version"]
    ]
    if len(participants) < REQUIRED_PARTICIPANTS:
        new_state = "waiting"
    elif len(current_confirmations) == len(participants):
        new_state = "verified"
    elif current_confirmations:
        new_state = "confirming"
    else:
        new_state = "ready"

    if new_state != verification["state"]:
        completed_at = now if new_state == "verified" else None
        conn.execute(
            """
            UPDATE verifications
               SET state = ?, completed_at = COALESCE(?, completed_at),
                   version = version + 1
             WHERE id = ?
            """,
            (new_state, completed_at, verification["id"]),
        )
        verification["state"] = new_state
        verification["version"] += 1
        if completed_at:
            verification["completed_at"] = completed_at
        db.audit(
            conn,
            verification_id=verification["id"],
            actor_id=None,
            event_type=new_state,
        )
        if new_state == "verified":
            _create_receipt(conn, config, verification)

    if commit:
        conn.commit()
    return verification


def _create_receipt(
    conn: sqlite3.Connection, config: Config, verification: dict[str, Any]
) -> dict[str, Any]:
    existing = conn.execute(
        "SELECT * FROM receipts WHERE verification_id = ?", (verification["id"],)
    ).fetchone()
    if existing:
        return dict(existing)

    participants = _participants(conn, verification["id"])
    payload = {
        "app": config.app_name,
        "version": config.version,
        "reference": verification["public_ref"],
        "kind": verification["kind"],
        "kind_label": security.kind_label(verification["kind"]),
        "context": verification["context"],
        "verified_at": verification.get("completed_at") or security.iso(),
        "participants": [
            {
                "role": p["role"],
                "role_label": security.role_label(p["role"]),
                "name": p["display_name"],
                "assurance": p["assurance"],
                "assurance_label": security.assurance_label(
                    p["assurance"], mock=config.auth_mode == "dev"
                ),
                "org": p["org"],
                "pn_masked": p["pn_masked"] or "—",
            }
            for p in participants
        ],
        "method": "Each participant read their own code aloud and the other participant verified it in the same session.",
        "disclaimer": "This receipt confirms account presence in a verification session. It does not prove the voice or video channel is authentic.",
    }
    receipt_id = security.new_id()
    integrity = security.receipt_hmac(config.secret_key, payload)
    conn.execute(
        """
        INSERT OR IGNORE INTO receipts
            (id, verification_id, payload, integrity_hmac, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            receipt_id,
            verification["id"],
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
            integrity,
            security.iso(),
        ),
    )
    db.audit(
        conn,
        verification_id=verification["id"],
        actor_id=None,
        event_type="receipt.created",
        data={"receipt_id": receipt_id},
    )
    return dict(
        conn.execute(
            "SELECT * FROM receipts WHERE verification_id = ?", (verification["id"],)
        ).fetchone()
    )


def get_view(
    config: Config,
    verification_id: str,
    user_id: str,
    *,
    base_url: str,
) -> dict[str, Any]:
    conn = db.connect(config)
    try:
        verification = _fetch(conn, verification_id)
        if not verification:
            raise VerificationError(404, "not_found", "Verification not found")
        verification = _refresh(conn, config, verification, commit=True)
        return _build_view(conn, config, verification, user_id, base_url)
    finally:
        conn.close()


def _ensure_participant_codes(
    conn: sqlite3.Connection, participants: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Backfill per-person codes for sessions created before the schema change."""
    missing = [p for p in participants if not p["code"]]
    if not missing:
        return participants
    for participant in missing:
        conn.execute(
            "UPDATE participants SET code = ?, words = ? WHERE id = ?",
            (
                _unique_participant_code(conn, participant["verification_id"]),
                json.dumps(security.new_words(), ensure_ascii=False),
                participant["id"],
            ),
        )
    conn.commit()
    verification_id = participants[0]["verification_id"]
    return _participants(conn, verification_id)


def _build_view(
    conn: sqlite3.Connection,
    config: Config,
    verification: dict[str, Any],
    user_id: str,
    base_url: str,
) -> dict[str, Any]:
    participants = _ensure_participant_codes(
        conn, _participants(conn, verification["id"])
    )
    me = next((p for p in participants if p["user_id"] == user_id), None)
    if not me:
        raise VerificationError(403, "forbidden", "You are not a participant in this verification")
    other = next((p for p in participants if p["user_id"] != user_id), None)

    participant_views = []
    for p in participants:
        # A participant always sees their own number. Another participant's
        # number is shown only after that person explicitly reveals it. The
        # session creator's pn_mode choice must never disclose someone else's
        # personal number without their consent.
        show_full = p["user_id"] == user_id or bool(p["revealed_at"])
        pn = (
            security.decrypt_value(
                config.secret_key, config.pn_encryption_key, p["pn_encrypted"]
            )
            if show_full
            else None
        )
        participant_views.append(
            {
                "user_id": p["user_id"],
                "role": p["role"],
                "role_label": security.role_label(p["role"]),
                "name": p["display_name"],
                "initials": security.initials(p["display_name"]),
                "assurance": p["assurance"],
                "assurance_label": security.assurance_label(
                    p["assurance"], mock=config.auth_mode == "dev"
                ),
                "org": p["org"],
                "pn": pn,
                "pn_masked": p["pn_masked"] or "—",
                "pn_shared": bool(pn),
                "revealed": bool(p["revealed_at"]),
                "is_me": p["user_id"] == user_id,
                "confirmed": (
                    p["decision"] == "match"
                    and p["confirmed_roster_version"] == verification["roster_version"]
                ),
                "decision": p["decision"],
                "confirmed_at": p["confirmed_at"],
                "can_reveal": (
                    p["user_id"] == user_id
                    and not p["revealed_at"]
                    and bool(p["pn_encrypted"])
                ),
            }
        )

    my_view = next(p for p in participant_views if p["is_me"])
    other_view = next((p for p in participant_views if not p["is_me"]), None)
    my_code = me["code"] or ""
    my_words = json.loads(me["words"]) if me["words"] else []

    join_url_value = None
    if (
        me["role"] == "initiator"
        and not verification["join_token_used_at"]
        and verification["state"] in {"waiting", "ready"}
    ):
        token = security.decrypt_value(
            config.secret_key, config.pn_encryption_key, verification["join_token_enc"]
        )
        if token:
            join_url_value = security.join_url(base_url, token)

    receipt = None
    receipt_row = conn.execute(
        "SELECT * FROM receipts WHERE verification_id = ?", (verification["id"],)
    ).fetchone()
    if receipt_row:
        receipt = {
            "id": receipt_row["id"],
            "payload": json.loads(receipt_row["payload"]),
            "integrity_hmac": receipt_row["integrity_hmac"],
            "created_at": receipt_row["created_at"],
        }

    return {
        "id": verification["id"],
        "public_ref": verification["public_ref"],
        "kind": verification["kind"],
        "kind_label": security.kind_label(verification["kind"]),
        "state": verification["state"],
        "state_label": security.state_label(verification["state"]),
        "context": verification["context"],
        "pn_mode": verification["pn_mode"],
        "my_code": my_code,
        "my_words": my_words,
        "roster_version": verification["roster_version"],
        "created_at": verification["created_at"],
        "expires_at": verification["expires_at"],
        "completed_at": verification["completed_at"],
        "join_url": join_url_value,
        "participants": participant_views,
        "me": my_view,
        "other": other_view,
        "my_confirmed": my_view["confirmed"],
        "other_confirmed": bool(other_view and other_view["confirmed"]),
        "can_verify": (
            verification["state"] in {"ready", "confirming"} and not my_view["confirmed"]
        ),
        "can_cancel": verification["state"] not in TERMINAL,
        "receipt": receipt,
        "dev_counterpart": (
            auth.counterpart_for(me["subject"]) if config.auth_mode == "dev" else None
        ),
    }


def get_invite(config: Config, token: str, user_id: str) -> dict[str, Any]:
    conn = db.connect(config)
    try:
        row = conn.execute(
            "SELECT * FROM verifications WHERE join_token_hash = ?",
            (security.token_hash(token),),
        ).fetchone()
        if not row:
            raise VerificationError(404, "not_found", "This invite link is not valid")
        verification = dict(row)
        verification = _refresh(conn, config, verification, commit=True)
        if verification["state"] in TERMINAL:
            raise VerificationError(410, "expired", "This verification is no longer active")
        if verification["join_token_used_at"]:
            participants = _participants(conn, verification["id"])
            if any(p["user_id"] == user_id for p in participants):
                return {"already_joined": True, "verification_id": verification["id"]}
            raise VerificationError(410, "used", "This invite link has already been used")

        participants = _participants(conn, verification["id"])
        initiator = next((p for p in participants if p["role"] == "initiator"), None)
        if not initiator:
            raise VerificationError(500, "invalid", "This verification has no initiator")
        if any(p["user_id"] == user_id for p in participants):
            return {"already_joined": True, "verification_id": verification["id"]}

        return {
            "already_joined": False,
            "verification_id": verification["id"],
            "public_ref": verification["public_ref"],
            "kind": verification["kind"],
            "kind_label": security.kind_label(verification["kind"]),
            "context": verification["context"],
            "pn_mode": verification["pn_mode"],
            "expires_at": verification["expires_at"],
            "initiator": {
                "name": initiator["display_name"],
                "initials": security.initials(initiator["display_name"]),
                "assurance": initiator["assurance"],
                "assurance_label": security.assurance_label(
                    initiator["assurance"], mock=config.auth_mode == "dev"
                ),
                "org": initiator["org"],
                "pn_masked": initiator["pn_masked"] or "—",
            },
        }
    finally:
        conn.close()


def join_verification(
    config: Config,
    auth_ctx: auth.AuthContext,
    verification_id: str,
    token: str,
    *,
    base_url: str,
    ip_hash: str | None = None,
    ua_hash: str | None = None,
) -> dict[str, Any]:
    conn = db.connect(config)
    try:
        conn.execute("BEGIN IMMEDIATE")
        verification = _fetch(conn, verification_id)
        if not verification:
            raise VerificationError(404, "not_found", "Verification not found")
        if not security.constant_time_equal(
            security.token_hash(token), verification["join_token_hash"]
        ):
            raise VerificationError(404, "not_found", "This invite link is not valid")

        participants = _participants(conn, verification_id)
        if any(p["user_id"] == auth_ctx.user["id"] for p in participants):
            conn.commit()
            return _build_view(conn, config, verification, auth_ctx.user["id"], base_url)

        verification = _refresh(conn, config, verification, commit=False)
        if verification["state"] in TERMINAL:
            raise VerificationError(410, "expired", "This verification is no longer active")
        if verification["join_token_used_at"]:
            raise VerificationError(410, "used", "This invite link has already been used")
        if len(participants) >= REQUIRED_PARTICIPANTS:
            raise VerificationError(409, "full", "This verification already has two participants")

        _insert_participant(
            conn,
            config,
            verification_id,
            auth_ctx,
            role="responder",
            joined_at=security.iso(),
        )
        # A roster change invalidates earlier confirmations by construction.
        conn.execute(
            """
            UPDATE participants
               SET decision = NULL, confirmed_at = NULL, confirmed_roster_version = NULL
             WHERE verification_id = ?
            """,
            (verification_id,),
        )
        conn.execute(
            """
            UPDATE verifications
               SET join_token_used_at = ?, state = 'ready',
                   roster_version = roster_version + 1, version = version + 1
             WHERE id = ?
            """,
            (security.iso(), verification_id),
        )
        db.audit(
            conn,
            verification_id=verification_id,
            actor_id=auth_ctx.user["id"],
            event_type="joined",
            data={"role": "responder"},
            ip_hash=ip_hash,
            ua_hash=ua_hash,
        )
        conn.commit()
        verification = _fetch(conn, verification_id)
        return _build_view(conn, config, verification, auth_ctx.user["id"], base_url)
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def confirm(
    config: Config,
    auth_ctx: auth.AuthContext,
    verification_id: str,
    *,
    decision: str,
    roster_version: int,
    code: str = "",
    base_url: str,
    ip_hash: str | None = None,
    ua_hash: str | None = None,
) -> dict[str, Any]:
    if decision not in {"match", "no_match"}:
        raise VerificationError(400, "invalid_decision", "Invalid decision")
    try:
        roster_version = int(roster_version)
    except (TypeError, ValueError) as exc:
        raise VerificationError(400, "invalid_roster", "Invalid roster version") from exc
    conn = db.connect(config)
    try:
        conn.execute("BEGIN IMMEDIATE")
        verification = _fetch(conn, verification_id)
        if not verification:
            raise VerificationError(404, "not_found", "Verification not found")
        verification = _refresh(conn, config, verification, commit=False)
        if verification["state"] in TERMINAL:
            raise VerificationError(409, "terminal", "This verification is already closed")
        if verification["state"] not in {"ready", "confirming"}:
            raise VerificationError(
                409, "not_ready", "Both participants must join before confirmation"
            )
        if int(roster_version) != verification["roster_version"]:
            raise VerificationError(
                409, "stale_roster", "The participant list changed; refresh and confirm again"
            )
        participant = conn.execute(
            "SELECT * FROM participants WHERE verification_id = ? AND user_id = ?",
            (verification_id, auth_ctx.user["id"]),
        ).fetchone()
        if not participant:
            raise VerificationError(403, "forbidden", "You are not a participant")
        if participant["decision"] and participant["decision"] != decision:
            raise VerificationError(409, "already_decided", "You already made a decision")

        if decision == "match":
            other_participant = conn.execute(
                """
                SELECT * FROM participants
                 WHERE verification_id = ? AND user_id != ?
                 LIMIT 1
                """,
                (verification_id, auth_ctx.user["id"]),
            ).fetchone()
            if not other_participant:
                raise VerificationError(
                    409, "not_ready", "The other participant has not joined yet"
                )
            expected = security.normalize_code(other_participant["code"])
            supplied = security.normalize_code(code)
            if not expected or not supplied or not security.constant_time_equal(
                supplied, expected
            ):
                raise VerificationError(
                    422,
                    "invalid_code",
                    "The code does not match the other participant's code",
                )

        conn.execute(
            """
            UPDATE participants
               SET decision = ?, confirmed_at = ?, confirmed_roster_version = ?
             WHERE id = ?
            """,
            (decision, security.iso(), roster_version, participant["id"]),
        )
        db.audit(
            conn,
            verification_id=verification_id,
            actor_id=auth_ctx.user["id"],
            event_type="confirmed" if decision == "match" else "no_match",
            data={"decision": decision},
            ip_hash=ip_hash,
            ua_hash=ua_hash,
        )
        _refresh(conn, config, verification, commit=False)
        conn.commit()
        verification = _fetch(conn, verification_id)
        return _build_view(conn, config, verification, auth_ctx.user["id"], base_url)
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def reveal(
    config: Config,
    auth_ctx: auth.AuthContext,
    verification_id: str,
    *,
    base_url: str,
) -> dict[str, Any]:
    conn = db.connect(config)
    try:
        participant = conn.execute(
            "SELECT * FROM participants WHERE verification_id = ? AND user_id = ?",
            (verification_id, auth_ctx.user["id"]),
        ).fetchone()
        if not participant:
            raise VerificationError(403, "forbidden", "You are not a participant")
        conn.execute(
            "UPDATE participants SET revealed_at = ? WHERE id = ?",
            (security.iso(), participant["id"]),
        )
        db.audit(
            conn,
            verification_id=verification_id,
            actor_id=auth_ctx.user["id"],
            event_type="revealed_pn",
        )
        conn.commit()
        verification = _fetch(conn, verification_id)
        if not verification:
            raise VerificationError(404, "not_found", "Verification not found")
        return _build_view(conn, config, verification, auth_ctx.user["id"], base_url)
    finally:
        conn.close()


def cancel(
    config: Config,
    auth_ctx: auth.AuthContext,
    verification_id: str,
    *,
    base_url: str,
) -> dict[str, Any]:
    conn = db.connect(config)
    try:
        conn.execute("BEGIN IMMEDIATE")
        verification = _fetch(conn, verification_id)
        if not verification:
            raise VerificationError(404, "not_found", "Verification not found")
        participant = conn.execute(
            "SELECT 1 FROM participants WHERE verification_id = ? AND user_id = ?",
            (verification_id, auth_ctx.user["id"]),
        ).fetchone()
        if not participant:
            raise VerificationError(403, "forbidden", "You are not a participant")
        if verification["state"] not in TERMINAL:
            conn.execute(
                "UPDATE verifications SET state = 'cancelled', version = version + 1 WHERE id = ?",
                (verification_id,),
            )
            db.audit(
                conn,
                verification_id=verification_id,
                actor_id=auth_ctx.user["id"],
                event_type="cancelled",
            )
        conn.commit()
        return _build_view(
            conn, config, _fetch(conn, verification_id), auth_ctx.user["id"], base_url
        )
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def recent(config: Config, user_id: str) -> list[dict[str, Any]]:
    conn = db.connect(config)
    try:
        rows = conn.execute(
            """
            SELECT v.*
              FROM verifications v
              JOIN participants p ON p.verification_id = v.id
             WHERE p.user_id = ?
             ORDER BY v.created_at DESC
             LIMIT 20
            """,
            (user_id,),
        ).fetchall()
        summaries = []
        for row in rows:
            verification = _refresh(conn, config, dict(row), commit=True)
            participants = _participants(conn, verification["id"])
            me = next((p for p in participants if p["user_id"] == user_id), None)
            other = next((p for p in participants if p["user_id"] != user_id), None)
            receipt = conn.execute(
                "SELECT id FROM receipts WHERE verification_id = ?", (verification["id"],)
            ).fetchone()
            summaries.append(
                {
                    "id": verification["id"],
                    "public_ref": verification["public_ref"],
                    "kind": verification["kind"],
                    "kind_label": security.kind_label(verification["kind"]),
                    "state": verification["state"],
                    "state_label": security.state_label(verification["state"]),
                    "context": verification["context"],
                    "created_at": verification["created_at"],
                    "expires_at": verification["expires_at"],
                    "role": me["role"] if me else "member",
                    "other_name": other["display_name"] if other else None,
                    "receipt_id": receipt["id"] if receipt else None,
                }
            )
        return summaries
    finally:
        conn.close()


def receipt_view(config: Config, receipt_id: str, user_id: str) -> dict[str, Any]:
    conn = db.connect(config)
    try:
        row = conn.execute(
            """
            SELECT r.*, v.public_ref, v.kind, v.context
              FROM receipts r
              JOIN verifications v ON v.id = r.verification_id
             WHERE r.id = ?
            """,
            (receipt_id,),
        ).fetchone()
        if not row:
            raise VerificationError(404, "not_found", "Receipt not found")
        participant = conn.execute(
            "SELECT 1 FROM participants WHERE verification_id = ? AND user_id = ?",
            (row["verification_id"], user_id),
        ).fetchone()
        if not participant:
            raise VerificationError(403, "forbidden", "You cannot view this receipt")
        return {
            "id": row["id"],
            "verification_id": row["verification_id"],
            "payload": json.loads(row["payload"]),
            "integrity_hmac": row["integrity_hmac"],
            "created_at": row["created_at"],
        }
    finally:
        conn.close()


def cleanup(config: Config) -> None:
    conn = db.connect(config)
    try:
        db.cleanup(conn, config)
    finally:
        conn.close()
