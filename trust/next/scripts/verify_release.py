#!/usr/bin/env python3
"""Verify an immutable public release manifest and its GitHub approvals."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True
import verify_authenticity


TRUSTED_ASSOCIATIONS = {"OWNER", "MEMBER", "COLLABORATOR"}
REQUIRED_ROLES = {"clinical-safety", "security", "operations"}
LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
RELEASE_ID = re.compile(r"^rel-[0-9]{8}t[0-9]{6}z-[0-9a-f]{12}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
MAX_JSON_BYTES = 32 * 1024


class VerificationError(Exception):
    pass


def parse_time(value: object, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as error:
        raise VerificationError(f"{label} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise VerificationError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def canonical_sha256(document: dict[str, Any]) -> str:
    canonical = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def require_exact_keys(document: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(document)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise VerificationError(
            f"{label} keys are invalid (missing={missing}, extra={extra})"
        )


def load_json(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise VerificationError(f"cannot inspect {path}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise VerificationError(f"{path} must be a regular non-symlink file")
    if metadata.st_size > MAX_JSON_BYTES:
        raise VerificationError(f"{path} exceeds the JSON size limit")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"{path} is not valid UTF-8 JSON") from error
    if not isinstance(document, dict):
        raise VerificationError(f"{path} must contain a JSON object")
    return document


def validate_policy(document: dict[str, Any]) -> dict[str, Any]:
    require_exact_keys(
        document,
        {
            "schemaVersion",
            "bootstrapComplete",
            "defaultBranch",
            "maximumApprovalHours",
            "authenticity",
            "roleApprovers",
        },
        "policy",
    )
    if document["schemaVersion"] != 1 or document["defaultBranch"] != "main":
        raise VerificationError("policy schema or default branch is unsupported")
    try:
        authenticity = verify_authenticity.validate_authenticity_policy(
            document["authenticity"]
        )
    except verify_authenticity.VerificationError as error:
        raise VerificationError(f"policy authenticity settings are invalid: {error}") from error
    if document["bootstrapComplete"] is not True:
        raise VerificationError("release control bootstrap is not complete")
    if authenticity["signingConfigured"] is not True:
        raise VerificationError(
            "release control bootstrap requires configured authenticity signing"
        )
    hours = document["maximumApprovalHours"]
    if not isinstance(hours, int) or isinstance(hours, bool) or not 1 <= hours <= 24:
        raise VerificationError("maximumApprovalHours must be an integer from 1 to 24")
    roles = document["roleApprovers"]
    if not isinstance(roles, dict) or set(roles) != REQUIRED_ROLES:
        raise VerificationError(
            "policy must define clinical-safety, security, and operations approvers"
        )
    seen: set[str] = set()
    normalized: dict[str, list[str]] = {}
    for role in sorted(REQUIRED_ROLES):
        values = roles[role]
        if not isinstance(values, list) or not values:
            raise VerificationError(f"{role} must have at least one authorized approver")
        logins: list[str] = []
        for value in values:
            if not isinstance(value, str) or not LOGIN.fullmatch(value):
                raise VerificationError(f"{role} contains an invalid GitHub login")
            login = value.lower()
            if login in seen:
                raise VerificationError("one person cannot hold multiple release approval roles")
            seen.add(login)
            logins.append(login)
        if len(logins) != len(set(logins)):
            raise VerificationError(f"{role} contains duplicate approvers")
        normalized[role] = logins
    return {
        **document,
        "authenticity": authenticity,
        "roleApprovers": normalized,
    }


def validate_manifest(
    document: dict[str, Any],
    policy: dict[str, Any],
    now: datetime | None = None,
    require_current: bool = True,
) -> dict[str, Any]:
    require_exact_keys(
        document,
        {
            "schemaVersion",
            "releaseId",
            "environment",
            "sourceCommit",
            "artifacts",
            "sourceReviewEvidenceSha256",
            "clinicalSafetyEvidenceSha256",
            "promotionEvidenceSha256",
            "releaseSetManifestSha256",
            "combinedIdentitySha256",
            "stagingManifestSha256",
            "approvalIssue",
            "createdAt",
            "expiresAt",
        },
        "manifest",
    )
    if document["schemaVersion"] != 1:
        raise VerificationError("manifest schema is unsupported")
    if not isinstance(document["releaseId"], str) or not RELEASE_ID.fullmatch(
        document["releaseId"]
    ):
        raise VerificationError("releaseId is invalid")
    if document["environment"] not in {"staging", "prod"}:
        raise VerificationError("environment must be staging or prod")
    if not isinstance(document["sourceCommit"], str) or not COMMIT.fullmatch(
        document["sourceCommit"]
    ):
        raise VerificationError("sourceCommit must be a full lowercase Git SHA")
    artifacts = document["artifacts"]
    if not isinstance(artifacts, dict):
        raise VerificationError("artifacts must be an object")
    require_exact_keys(
        artifacts,
        {"apiSha256", "collectorSha256", "alertmanagerSha256"},
        "artifacts",
    )
    for name, value in artifacts.items():
        if not isinstance(value, str) or not DIGEST.fullmatch(value):
            raise VerificationError(f"{name} must be a lowercase SHA-256 digest")
    for evidence_name in (
        "sourceReviewEvidenceSha256",
        "clinicalSafetyEvidenceSha256",
        "promotionEvidenceSha256",
    ):
        if not isinstance(document[evidence_name], str) or not DIGEST.fullmatch(
            document[evidence_name]
        ):
            raise VerificationError(f"{evidence_name} must be a SHA-256 digest")
    for binding_name in ("releaseSetManifestSha256", "combinedIdentitySha256"):
        value = document[binding_name]
        if not isinstance(value, str) or not DIGEST.fullmatch(value):
            raise VerificationError(
                f"{binding_name} must be a lowercase SHA-256 digest"
            )
        if value != verify_authenticity.EXPECTED_REQUEST[binding_name]:
            raise VerificationError(
                f"{binding_name} does not match the canonical authenticity request"
            )
    staging_hash = document["stagingManifestSha256"]
    if document["environment"] == "staging" and staging_hash is not None:
        raise VerificationError("stagingManifestSha256 must be null for staging")
    if document["environment"] == "prod" and (
        not isinstance(staging_hash, str) or not DIGEST.fullmatch(staging_hash)
    ):
        raise VerificationError("production must bind a staging manifest SHA-256")
    issue = document["approvalIssue"]
    if not isinstance(issue, int) or isinstance(issue, bool) or issue <= 0:
        raise VerificationError("approvalIssue must be a positive integer")
    created = parse_time(document["createdAt"], "createdAt")
    expires = parse_time(document["expiresAt"], "expiresAt")
    checked_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if created > checked_at + timedelta(minutes=5):
        raise VerificationError("manifest creation time is in the future")
    if require_current and expires <= checked_at:
        raise VerificationError("manifest is expired")
    if expires <= created or expires > created + timedelta(
        hours=policy["maximumApprovalHours"]
    ):
        raise VerificationError("manifest approval window exceeds policy")
    return document


def validate_manifest_path(path: Path, repository_root: Path, manifest: dict[str, Any]) -> None:
    releases = (repository_root / "releases").resolve()
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise VerificationError("manifest path cannot be resolved") from error
    if resolved.parent != releases or resolved.suffix != ".json":
        raise VerificationError("manifest must be a direct JSON child of releases/")
    if resolved.stem != manifest["releaseId"]:
        raise VerificationError("manifest filename must equal releaseId")


def validate_production_promotion(
    manifest: dict[str, Any], repository_root: Path, policy: dict[str, Any], now: datetime
) -> None:
    if manifest["environment"] != "prod":
        return
    expected_hash = manifest["stagingManifestSha256"]
    matches: list[dict[str, Any]] = []
    for path in sorted((repository_root / "releases").glob("*.json")):
        candidate = load_json(path)
        if canonical_sha256(candidate) == expected_hash:
            matches.append(validate_manifest(candidate, policy, now, require_current=False))
    if len(matches) != 1:
        raise VerificationError("production must bind exactly one committed staging manifest")
    staging = matches[0]
    if staging["environment"] != "staging":
        raise VerificationError("bound promotion manifest is not for staging")
    if (
        staging["sourceCommit"] != manifest["sourceCommit"]
        or staging["artifacts"] != manifest["artifacts"]
        or staging["sourceReviewEvidenceSha256"]
        != manifest["sourceReviewEvidenceSha256"]
        or staging["clinicalSafetyEvidenceSha256"]
        != manifest["clinicalSafetyEvidenceSha256"]
        or staging["releaseSetManifestSha256"]
        != manifest["releaseSetManifestSha256"]
        or staging["combinedIdentitySha256"]
        != manifest["combinedIdentitySha256"]
    ):
        raise VerificationError("production artifacts differ from the staged candidate")


def marker(text: str, label: str, pattern: str) -> str:
    matches = re.findall(rf"^{re.escape(label)}:\s*({pattern})\s*$", text, re.MULTILINE)
    if len(matches) != 1:
        raise VerificationError(f"approval record requires exactly one {label}")
    return matches[0].strip()


def approval_request(manifest: dict[str, Any], manifest_sha256: str) -> str:
    return "\n".join(
        (
            "PUBLIC-RELEASE-APPROVAL-REQUEST: 1",
            f"Release-ID: {manifest['releaseId']}",
            f"Environment: {manifest['environment']}",
            f"Manifest-SHA256: {manifest_sha256}",
            f"Expires-At: {manifest['expiresAt']}",
        )
    )


def parse_request(body: str) -> dict[str, str]:
    if marker(body, "PUBLIC-RELEASE-APPROVAL-REQUEST", r"\d+") != "1":
        raise VerificationError("approval request schema is unsupported")
    return {
        "releaseId": marker(body, "Release-ID", r"\S+"),
        "environment": marker(body, "Environment", r"\S+"),
        "manifestSha256": marker(body, "Manifest-SHA256", r"\S+"),
        "expiresAt": marker(body, "Expires-At", r"\S+"),
    }


def parse_comment(body: str) -> dict[str, str] | None:
    if not re.search(r"^PUBLIC-RELEASE-APPROVED:", body, re.MULTILINE):
        return None
    try:
        if marker(body, "PUBLIC-RELEASE-APPROVED", r"\d+") != "1":
            return None
        return {
            "environment": marker(body, "Environment", r"\S+"),
            "manifestSha256": marker(body, "Manifest-SHA256", r"\S+"),
            "role": marker(body, "Role", r"[a-z-]+"),
            "decision": marker(body, "Decision", r"[a-z]+"),
            "evidence": marker(body, "Evidence", r"\S.{7,159}"),
        }
    except VerificationError:
        return None


def verify_approvals(
    issue: dict[str, Any],
    comments: list[dict[str, Any]],
    manifest: dict[str, Any],
    policy: dict[str, Any],
    initiator: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    checked_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    manifest_hash = canonical_sha256(manifest)
    findings: list[str] = []
    if issue.get("pull_request"):
        findings.append("approval reference is a pull request")
    if issue.get("number") != manifest["approvalIssue"]:
        findings.append("approval issue number does not match manifest")
    if issue.get("state") != "closed" or issue.get("state_reason") != "completed":
        findings.append("approval issue must be closed as completed")

    try:
        issue_created = parse_time(issue.get("created_at"), "issue created_at")
        issue_closed = parse_time(issue.get("closed_at"), "issue closed_at")
    except VerificationError as error:
        issue_created = checked_at
        issue_closed = checked_at
        findings.append(str(error))
    manifest_created = parse_time(manifest["createdAt"], "createdAt")
    expires = parse_time(manifest["expiresAt"], "expiresAt")
    if issue_closed < max(issue_created, manifest_created) or issue_closed >= expires:
        findings.append("approval issue closure is outside the approval window")
    if issue_closed > checked_at + timedelta(minutes=5):
        findings.append("approval issue closure is in the future")

    expected_request = {
        "releaseId": manifest["releaseId"],
        "environment": manifest["environment"],
        "manifestSha256": manifest_hash,
        "expiresAt": manifest["expiresAt"],
    }
    try:
        request = parse_request(str(issue.get("body") or ""))
        for key, expected in expected_request.items():
            if request[key] != expected:
                findings.append(f"approval request {key} does not match manifest")
        if str(issue.get("body") or "").strip() != approval_request(
            manifest, manifest_hash
        ):
            findings.append("approval request contains unapproved public content")
    except VerificationError as error:
        findings.append(str(error))

    issue_user = issue.get("user")
    issue_author = (
        str(issue_user.get("login", "")).lower()
        if isinstance(issue_user, dict)
        else ""
    )
    if not LOGIN.fullmatch(issue_author):
        findings.append("approval issue author is invalid")
    approved_roles: set[str] = set()
    used_people: set[str] = set()
    for comment in comments:
        parsed = parse_comment(str(comment.get("body") or ""))
        if parsed is None:
            continue
        user = comment.get("user")
        login = str(user.get("login", "")).lower() if isinstance(user, dict) else ""
        user_type = str(user.get("type", "")) if isinstance(user, dict) else ""
        role = parsed["role"]
        try:
            created = parse_time(comment.get("created_at"), "comment created_at")
            updated = parse_time(comment.get("updated_at"), "comment updated_at")
        except VerificationError:
            continue
        authorized = role in REQUIRED_ROLES and login in policy["roleApprovers"].get(
            role, []
        )
        if (
            not authorized
            or parsed["decision"] != "approve"
            or parsed["environment"] != manifest["environment"]
            or parsed["manifestSha256"] != manifest_hash
            or role in approved_roles
            or login in used_people
            or login in {issue_author, initiator.lower()}
            or user_type == "Bot"
            or comment.get("author_association") not in TRUSTED_ASSOCIATIONS
            or created != updated
            or created < max(issue_created, manifest_created)
            or created > checked_at + timedelta(minutes=5)
            or created >= min(issue_closed, expires)
            or "<" in parsed["evidence"]
            or ">" in parsed["evidence"]
            or parsed["evidence"] != "reviewed private immutable release evidence"
            or re.search(r"\b(?:placeholder|todo|tbd)\b", parsed["evidence"], re.I)
        ):
            continue
        approved_roles.add(role)
        used_people.add(login)

    missing = sorted(REQUIRED_ROLES - approved_roles)
    if missing:
        findings.append("missing authorized independent approvals: " + ", ".join(missing))
    return {
        "schemaVersion": 1,
        "generatedAt": checked_at.isoformat(),
        "releaseId": manifest["releaseId"],
        "environment": manifest["environment"],
        "sourceCommit": manifest["sourceCommit"],
        "manifestSha256": manifest_hash,
        "artifactDigests": manifest["artifacts"],
        "sourceReviewEvidenceSha256": manifest["sourceReviewEvidenceSha256"],
        "clinicalSafetyEvidenceSha256": manifest["clinicalSafetyEvidenceSha256"],
        "promotionEvidenceSha256": manifest["promotionEvidenceSha256"],
        "releaseSetManifestSha256": manifest["releaseSetManifestSha256"],
        "combinedIdentitySha256": manifest["combinedIdentitySha256"],
        "stagingManifestSha256": manifest["stagingManifestSha256"],
        "approvalIssue": manifest["approvalIssue"],
        "requiredRoles": sorted(REQUIRED_ROLES),
        "approvedRoles": sorted(approved_roles),
        "approvalCount": len(approved_roles),
        "findings": findings,
        "result": "verified" if not findings else "unverified",
    }


def gh_api(endpoint: str, paginate: bool = False) -> Any:
    environment = os.environ.copy()
    if not environment.get("GH_TOKEN") and environment.get("GITHUB_TOKEN"):
        environment["GH_TOKEN"] = environment["GITHUB_TOKEN"]
    command = ["gh", "api"]
    if paginate:
        command.extend(("--paginate", "--slurp"))
    command.append(endpoint)
    for attempt in range(3):
        try:
            completed = subprocess.run(
                command,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
            return json.loads(completed.stdout)
        except subprocess.CalledProcessError as error:
            if attempt == 2 or not re.search(r"HTTP (?:429|5\d\d)", error.stderr):
                raise VerificationError("GitHub approval evidence is unavailable") from error
            time.sleep(0.5 * 2**attempt)
        except (OSError, json.JSONDecodeError) as error:
            raise VerificationError("GitHub approval evidence is unavailable") from error
    raise AssertionError("unreachable")


def flatten_comments(document: Any) -> list[dict[str, Any]]:
    if not isinstance(document, list):
        raise VerificationError("GitHub comments response is invalid")
    records = (
        [item for page in document for item in page]
        if document and all(isinstance(page, list) for page in document)
        else document
    )
    if not all(isinstance(item, dict) for item in records):
        raise VerificationError("GitHub comments response is invalid")
    return records


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise VerificationError("report path cannot be a symlink")
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, delete=False
    ) as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
        temporary = Path(stream.name)
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--policy", default="release-control-policy.json")
    parser.add_argument("--repository")
    parser.add_argument("--initiator")
    parser.add_argument("--output")
    parser.add_argument("--print-request", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        policy_path = root / args.policy
        if policy_path.parent.resolve() != root or policy_path.name != "release-control-policy.json":
            raise VerificationError("policy must be release-control-policy.json at repository root")
        policy = validate_policy(load_json(policy_path))
        manifest_path = root / args.manifest
        manifest = validate_manifest(load_json(manifest_path), policy)
        validate_manifest_path(manifest_path, root, manifest)
        if args.print_request:
            print(approval_request(manifest, canonical_sha256(manifest)))
            return 0
        if not args.repository or not REPOSITORY.fullmatch(args.repository):
            raise VerificationError("repository must use owner/name form")
        if not args.initiator or not LOGIN.fullmatch(args.initiator):
            raise VerificationError("initiator must be a valid GitHub login")
        checked_at = datetime.now(timezone.utc)
        validate_production_promotion(manifest, root, policy, checked_at)
        issue = gh_api(f"repos/{args.repository}/issues/{manifest['approvalIssue']}")
        if not isinstance(issue, dict):
            raise VerificationError("GitHub approval issue response is invalid")
        comments = flatten_comments(
            gh_api(
                f"repos/{args.repository}/issues/{manifest['approvalIssue']}/comments?per_page=100",
                paginate=True,
            )
        )
        report = verify_approvals(issue, comments, manifest, policy, args.initiator)
        if args.output:
            output_path = Path(args.output).expanduser()
            if not output_path.is_absolute():
                raise VerificationError("output path must be absolute")
            write_report(output_path, report)
        else:
            print(json.dumps(report, indent=2))
        return 0 if report["result"] == "verified" else 1
    except (OSError, ValueError, VerificationError) as error:
        print(f"release verification failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
