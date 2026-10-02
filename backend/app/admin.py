"""Admin review of false-positive reports: sign-in, sessions, and the decisions.

Sign-in is email + password + a TOTP code. The password is never stored, only a
PBKDF2 verifier; the TOTP secret and the session key live in the environment
beside it. A verified sign-in mints a signed, expiring session token so the code
is typed once rather than on every request.

Approving a report clears that exact URL for every user, which makes this the
most powerful action in the product. Three things keep it honest: an approval is
recorded with who made it and when, it can be lifted again, and it never
overrides a live threat-feed listing (see policy.analyze).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from datetime import datetime, timezone
from typing import Optional

from . import history, totp
from .config import settings
from .models import AnalyzeResponse

logger = logging.getLogger("phisang")

PBKDF2_ROUNDS = 600_000
# A six-digit code is a small space, so wrong answers are what gets limited.
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 900
MAX_NOTE_CHARS = 1000

_attempts: dict[str, list[float]] = {}
# A code accepted once must not be accepted again inside its window.
_spent_codes: set[tuple[str, int]] = set()


class AdminError(RuntimeError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def configured() -> bool:
    return bool(settings.admin_email and settings.admin_password_hash
                and settings.admin_totp_secret and settings.admin_session_secret)


# --- passwords --------------------------------------------------------------

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return (f"pbkdf2_sha256${PBKDF2_ROUNDS}$"
            f"{base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}")


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, rounds, salt, expected = stored.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                     base64.b64decode(salt), int(rounds))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(base64.b64encode(digest).decode(), expected)


# --- sessions ---------------------------------------------------------------

def _sign(payload: str) -> str:
    return hmac.new(settings.admin_session_secret.encode("utf-8"),
                    payload.encode("utf-8"), hashlib.sha256).hexdigest()


def issue_session(email: str) -> dict:
    expires = int(time.time()) + settings.admin_session_minutes * 60
    payload = json.dumps({"email": email, "exp": expires}, separators=(",", ":"))
    body = base64.urlsafe_b64encode(payload.encode("utf-8")).decode().rstrip("=")
    return {"token": f"{body}.{_sign(body)}", "expires_at": expires}


def session_email(token: str) -> Optional[str]:
    """The signed-in address, or None for a missing, forged or expired token."""
    try:
        body, signature = (token or "").split(".", 1)
    except ValueError:
        return None
    if not hmac.compare_digest(_sign(body), signature):
        return None
    try:
        padded = body + "=" * (-len(body) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, TypeError):
        return None
    if claims.get("exp", 0) <= time.time():
        return None
    return claims.get("email")


def require_session(token: str) -> str:
    email = session_email(token)
    if not email:
        raise AdminError(401, "Your session has expired. Please sign in again.")
    return email


# --- sign-in ----------------------------------------------------------------

def _rate_limit(client: str) -> None:
    now = time.time()
    recent = [at for at in _attempts.get(client, []) if now - at < LOCKOUT_SECONDS]
    _attempts[client] = recent
    if len(recent) >= MAX_ATTEMPTS:
        raise AdminError(429, "Too many sign-in attempts. Try again later.")


def sign_in(email: str, password: str, code: str, *, client: str = "unknown") -> dict:
    if not configured():
        raise AdminError(503, "Admin review is not configured on this server.")
    _rate_limit(client)

    # One message for every failure: which of the three was wrong is not the
    # caller's business, and saying so would narrow the search for an attacker.
    counter = totp.verify(settings.admin_totp_secret, code)
    ok = (hmac.compare_digest((email or "").strip().lower(), settings.admin_email.strip().lower())
          and verify_password(password or "", settings.admin_password_hash)
          and counter is not None
          and (settings.admin_email, counter) not in _spent_codes)
    if not ok:
        _attempts.setdefault(client, []).append(time.time())
        logger.warning("admin sign-in refused client=%s", client)
        raise AdminError(401, "Wrong email, password or code.")

    _spent_codes.add((settings.admin_email, counter))
    # The set only needs the live window; anything older can never be replayed.
    for spent in [item for item in _spent_codes if item[1] < counter - totp.DRIFT_STEPS - 1]:
        _spent_codes.discard(spent)
    _attempts.pop(client, None)
    logger.info("admin signed in client=%s", client)
    return issue_session(settings.admin_email)


# --- reports ----------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _when(value) -> Optional[str]:
    return value.isoformat() if value is not None else None


def list_reports(status: str = "new", limit: int = 50) -> list[dict]:
    """One entry per address, not per report.

    Several people can object to the same verdict, and a reviewer decides about
    the address once. Each entry therefore carries every report filed against it:
    their ids (so a single decision covers them all), their reasons, and how many
    there were. The newest report supplies the scan shown, since that is the
    verdict the latest objection was about.
    """
    rows: list[dict] = []
    with history._cursor() as cur:
        if cur is None:
            return rows
        # Reports are grouped after they are read, so the status filter is applied
        # to the finished group rather than to its individual rows.
        where = ""
        params = (max(limit, 1) * 10,)
        cur.execute(
            f"""
            SELECT TOP (%s) r.ReportId, r.ScanRef, r.NormalizedUrl, r.Client,
                   r.ReportedVerdict, r.ReportedClassification, r.ReportedRiskScore,
                   r.Reason, r.ReviewStatus, r.CreatedAt, r.ReviewedAt, r.ReviewedBy,
                   r.ReviewNote,
                   s.Host, s.ApprovedAt, s.ApprovedBy, s.ScanCount, s.MaliciousCount,
                   s.SafeCount, s.PotentiallyUnsafeCount, s.UnknownCount, s.EverMalicious,
                   s.FirstScannedAt, s.LastScannedAt, s.EffectiveVerdict,
                   scans.RawResponseJson
            FROM dbo.FalsePositiveReports AS r
            LEFT JOIN dbo.Sites AS s ON s.UrlHash = r.UrlHash
            OUTER APPLY (
                SELECT TOP 1 x.RawResponseJson FROM dbo.Scans AS x
                WHERE x.ScanRef = r.ScanRef
            ) AS scans
            {where}
            ORDER BY r.CreatedAt DESC
            """,
            params,
        )
        for row in cur.fetchall():
            scan = None
            if row.get("RawResponseJson"):
                try:
                    scan = AnalyzeResponse.model_validate_json(row["RawResponseJson"]).model_dump(mode="json")
                    scan.pop("limitations", None)  # Identical on every row; noise here.
                except ValueError:
                    logger.warning("report %s has an unreadable scan record", row["ReportId"])
            rows.append({
                "report_id": int(row["ReportId"]),
                "scan_ref": row["ScanRef"],
                "url": row["NormalizedUrl"],
                "host": row["Host"],
                "client": row["Client"],
                "reason": row["Reason"],
                "status": row["ReviewStatus"],
                "created_at": _when(row["CreatedAt"]),
                "reviewed_at": _when(row["ReviewedAt"]),
                "reviewed_by": row["ReviewedBy"],
                "review_note": row["ReviewNote"],
                # The verdict as it stood when the user objected to it.
                "reported": {
                    "verdict": row["ReportedVerdict"],
                    "classification": row["ReportedClassification"],
                    "risk_score": row["ReportedRiskScore"],
                },
                "site": {
                    "effective_verdict": row["EffectiveVerdict"],
                    "scan_count": row["ScanCount"],
                    "malicious_count": row["MaliciousCount"],
                    "safe_count": row["SafeCount"],
                    "potentially_unsafe_count": row["PotentiallyUnsafeCount"],
                    "unknown_count": row["UnknownCount"],
                    "ever_malicious": bool(row["EverMalicious"]) if row["EverMalicious"] is not None else None,
                    "first_scanned_at": _when(row["FirstScannedAt"]),
                    "last_scanned_at": _when(row["LastScannedAt"]),
                    "approved_at": _when(row["ApprovedAt"]),
                    "approved_by": row["ApprovedBy"],
                },
                "scan": scan,
            })
    return _group_by_address(rows, status, limit)


def _group_by_address(rows: list[dict], status: str, limit: int) -> list[dict]:
    groups: dict[str, dict] = {}
    for row in rows:  # Already newest first, so the first row seen is the newest.
        group = groups.get(row["url"])
        if group is None:
            group = groups[row["url"]] = {
                "url": row["url"], "host": row["host"], "site": row["site"],
                "scan": row["scan"], "reported": row["reported"],
                "report_ids": [], "reports": [], "clients": [],
                "last_reported_at": row["created_at"], "first_reported_at": row["created_at"],
                "reviewed_at": row["reviewed_at"], "reviewed_by": row["reviewed_by"],
                "review_note": row["review_note"],
            }
        group["report_ids"].append(row["report_id"])
        group["reports"].append({"report_id": row["report_id"], "reason": row["reason"],
                                 "client": row["client"], "created_at": row["created_at"],
                                 "status": row["status"]})
        if row["client"] and row["client"] not in group["clients"]:
            group["clients"].append(row["client"])
        group["first_reported_at"] = row["created_at"]

    result = []
    for group in groups.values():
        statuses = {report["status"] for report in group["reports"]}
        # Anything still unreviewed keeps the whole address in the queue.
        group["status"] = ("new" if "new" in statuses
                           else "approved" if group["site"].get("approved_at") else "rejected")
        group["report_count"] = len(group["report_ids"])
        if status in {"new", "approved", "rejected"} and group["status"] != status:
            continue
        result.append(group)
    return result[:limit]


def _apply_review(cur, report_id: int, decision: str, reviewer: str, note: str | None) -> Optional[dict]:
    cur.execute("SELECT UrlHash, NormalizedUrl FROM dbo.FalsePositiveReports WHERE ReportId = %s",
                (report_id,))
    report = cur.fetchone()
    if report is None:
        return None
    cur.execute(
        """
        UPDATE dbo.FalsePositiveReports
        SET ReviewStatus = %s, ReviewedAt = %s, ReviewedBy = %s, ReviewNote = %s
        WHERE ReportId = %s
        """,
        (decision, _now(), reviewer[:255], (note or "").strip()[:MAX_NOTE_CHARS] or None, report_id),
    )
    # Approval is a property of the address, not of the report, so a later report
    # about the same URL inherits it and lifting it is one update.
    cur.execute(
        "UPDATE dbo.Sites SET ApprovedAt = %s, ApprovedBy = %s WHERE UrlHash = %s",
        (_now() if decision == "approved" else None,
         reviewer[:255] if decision == "approved" else None, report["UrlHash"]),
    )
    logger.info("admin review report_id=%s decision=%s by=%s", report_id, decision, reviewer)
    return {"report_id": report_id, "status": decision, "url": report["NormalizedUrl"]}


def review(report_id: int, decision: str, reviewer: str, note: str | None = None) -> dict:
    """Approve or reject one report. Approving clears that URL for everyone."""
    done = review_many([report_id], decision, reviewer, note)
    if not done["reviewed"]:
        raise AdminError(404, "That report no longer exists.")
    return done["reviewed"][0]


def review_many(report_ids: list[int], decision: str, reviewer: str,
                note: str | None = None) -> dict:
    """The same decision across several reports, in one transaction.

    All of them land or none do: a batch that half-applied would leave the
    reviewer guessing which addresses are now cleared.
    """
    if decision not in {"approved", "rejected"}:
        raise AdminError(400, "A report is either approved or rejected.")
    if not report_ids:
        raise AdminError(400, "Select at least one report.")
    if not history.enabled():
        raise AdminError(503, "Admin review is unavailable: the database is not configured.")

    outcome = None
    with history._cursor() as cur:
        if cur is not None:
            reviewed, missing = [], []
            for report_id in report_ids:
                done = _apply_review(cur, report_id, decision, reviewer, note)
                (reviewed if done else missing).append(done or report_id)
            outcome = {"reviewed": reviewed, "missing": missing}
    if outcome is None:
        raise AdminError(503, "The decision could not be saved. Please try again.")
    return outcome


def is_url_approved(normalized_url: str) -> bool:
    """True when an admin has cleared this exact address."""
    if not history.enabled():
        return False
    approved = False
    with history._cursor() as cur:
        if cur is not None:
            cur.execute("SELECT ApprovedAt FROM dbo.Sites WHERE UrlHash = %s",
                        (history.url_hash(normalized_url),))
            row = cur.fetchone()
            approved = bool(row and row["ApprovedAt"])
    return approved
