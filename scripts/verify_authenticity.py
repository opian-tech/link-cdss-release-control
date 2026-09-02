#!/usr/bin/env python3
"""Validate the canonical release-set request and its optional Sigstore bundle."""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


EXPECTED_REQUEST = {
    "schemaVersion": 1,
    "kind": "link.release-set-authenticity",
    "releaseId": "diagnostic-order-billing-final-lock-g-a",
    "releaseSetManifestSha256": (
        "7c9a35f00c3b23457f47736ddb3eaabe66195cd829e2ca360a922c14a05c509e"
    ),
    "combinedIdentitySha256": (
        "891e8cad0ff697f62a7929e83dd4cd9db7a7f522ed0b3bb05a78f45e39d771d7"
    ),
}
POLICY_KEYS = {
    "signingConfigured",
    "expectedCertificateIdentity",
    "certificateOidcIssuer",
}
IDENTITY_PLACEHOLDER = "REPLACE_WITH_EXACT_PUBLIC_REPOSITORY_WORKFLOW_IDENTITY"
EXPECTED_CERTIFICATE_IDENTITY = (
    "https://github.com/opian-tech/link-cdss-release-control/.github/workflows/"
    "sign-authenticity-request.yml@refs/heads/main"
)
EXPECTED_ISSUER = "https://token.actions.githubusercontent.com"
MAX_REQUEST_BYTES = 4 * 1024
MAX_BUNDLE_BYTES = 256 * 1024


class VerificationError(Exception):
    pass


def canonical_bytes(document: dict[str, Any]) -> bytes:
    return (
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")


def read_regular_file(path: Path, maximum_bytes: int, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise VerificationError(
            f"{label} must be a readable regular non-symlink file"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise VerificationError(f"{label} must be a regular non-symlink file")
        if metadata.st_size > maximum_bytes:
            raise VerificationError(f"{label} exceeds its size limit")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > maximum_bytes:
            raise VerificationError(f"{label} exceeds its size limit")
        return raw
    except OSError as error:
        raise VerificationError(f"cannot read {label}: {path}") from error
    finally:
        os.close(descriptor)


def parse_json_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"{label} must be valid UTF-8 JSON") from error
    if not isinstance(document, dict):
        raise VerificationError(f"{label} must contain a JSON object")
    return document


def validate_request_bytes(raw: bytes) -> dict[str, Any]:
    document = parse_json_object(raw, "authenticity request")
    if (
        document != EXPECTED_REQUEST
        or set(document) != set(EXPECTED_REQUEST)
        or type(document.get("schemaVersion")) is not int
    ):
        raise VerificationError("authenticity request does not match the approved values")
    if raw != canonical_bytes(document):
        raise VerificationError(
            "authenticity request must be sorted compact JSON followed by one LF newline"
        )
    return document


def validate_request(path: Path) -> dict[str, Any]:
    return validate_request_bytes(
        read_regular_file(path, MAX_REQUEST_BYTES, "authenticity request")
    )


def validate_authenticity_policy(document: object) -> dict[str, Any]:
    if not isinstance(document, dict) or set(document) != POLICY_KEYS:
        raise VerificationError("authenticity policy keys are invalid")
    configured = document["signingConfigured"]
    identity = document["expectedCertificateIdentity"]
    issuer = document["certificateOidcIssuer"]
    if not isinstance(configured, bool):
        raise VerificationError("signingConfigured must be a boolean")
    if issuer != EXPECTED_ISSUER:
        raise VerificationError("certificate OIDC issuer must be the GitHub Actions issuer")
    if configured is False:
        if identity != IDENTITY_PLACEHOLDER:
            raise VerificationError("unconfigured authenticity policy must retain the placeholder")
        return document
    if identity != EXPECTED_CERTIFICATE_IDENTITY:
        raise VerificationError(
            "expected certificate identity must match the configured public repository workflow"
        )
    return document


def load_policy(path: Path) -> dict[str, Any]:
    raw = read_regular_file(path, 32 * 1024, "release control policy")
    document = parse_json_object(raw, "release control policy")
    if "authenticity" not in document:
        raise VerificationError("release control policy is missing authenticity settings")
    return validate_authenticity_policy(document["authenticity"])


def validate_bundle_bytes(raw: bytes) -> None:
    document = parse_json_object(raw, "Sigstore bundle")
    if not document:
        raise VerificationError("Sigstore bundle cannot be empty")


def verify_bundle(
    request: Path,
    bundle: Path,
    policy: dict[str, Any],
    cosign: str = "cosign",
) -> None:
    if policy["signingConfigured"] is not True:
        raise VerificationError("authenticity signing is not configured; bundles are prohibited")
    request_bytes = read_regular_file(
        request, MAX_REQUEST_BYTES, "authenticity request"
    )
    validate_request_bytes(request_bytes)
    bundle_bytes = read_regular_file(bundle, MAX_BUNDLE_BYTES, "Sigstore bundle")
    validate_bundle_bytes(bundle_bytes)
    try:
        with tempfile.TemporaryDirectory(prefix="link-authenticity-") as directory:
            private_root = Path(directory)
            private_request = private_root / "authenticity-request.json"
            private_bundle = private_root / "authenticity-request.sigstore.json"
            private_request.write_bytes(request_bytes)
            private_bundle.write_bytes(bundle_bytes)
            os.chmod(private_request, 0o600)
            os.chmod(private_bundle, 0o600)
            command = [
                cosign,
                "verify-blob",
                "--bundle",
                str(private_bundle),
                "--certificate-identity",
                policy["expectedCertificateIdentity"],
                "--certificate-oidc-issuer",
                policy["certificateOidcIssuer"],
                str(private_request),
            ]
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise VerificationError("could not execute Cosign bundle verification") from error
    if result.returncode != 0:
        raise VerificationError("Cosign rejected the authenticity bundle")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--cosign", default="cosign")
    args = parser.parse_args()
    try:
        validate_request(args.request)
        policy = load_policy(args.policy)
        if args.bundle is not None:
            verify_bundle(args.request, args.bundle, policy, args.cosign)
        print("release-set authenticity verification passed")
        return 0
    except VerificationError as error:
        print(f"release-set authenticity verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
