#!/usr/bin/env python3

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


sys.dont_write_bytecode = True
MODULE_PATH = Path(__file__).with_name("verify_release.py")
SPEC = importlib.util.spec_from_file_location("verify_release", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class PublicReleaseVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc)
        self.policy = MODULE.validate_policy(
            {
                "schemaVersion": 1,
                "bootstrapComplete": True,
                "defaultBranch": "main",
                "maximumApprovalHours": 24,
                "authenticity": {
                    "signingConfigured": True,
                    "expectedCertificateIdentity": (
                        "https://github.com/example/release-control/.github/workflows/"
                        "sign-authenticity-request.yml@refs/heads/main"
                    ),
                    "certificateOidcIssuer": "https://token.actions.githubusercontent.com",
                },
                "roleApprovers": {
                    "clinical-safety": ["clinical-reviewer"],
                    "security": ["security-reviewer"],
                    "operations": ["operations-reviewer"],
                },
            }
        )
        self.manifest = {
            "schemaVersion": 1,
            "releaseId": "rel-20260720t110000z-a1b2c3d4e5f6",
            "environment": "staging",
            "sourceCommit": "a" * 40,
            "artifacts": {
                "apiSha256": "b" * 64,
                "collectorSha256": "c" * 64,
                "alertmanagerSha256": "d" * 64,
            },
            "sourceReviewEvidenceSha256": "1" * 64,
            "clinicalSafetyEvidenceSha256": "2" * 64,
            "promotionEvidenceSha256": "e" * 64,
            "releaseSetManifestSha256": MODULE.verify_authenticity.EXPECTED_REQUEST[
                "releaseSetManifestSha256"
            ],
            "combinedIdentitySha256": MODULE.verify_authenticity.EXPECTED_REQUEST[
                "combinedIdentitySha256"
            ],
            "stagingManifestSha256": None,
            "approvalIssue": 91,
            "createdAt": (self.now - timedelta(hours=1)).isoformat(),
            "expiresAt": (self.now + timedelta(hours=2)).isoformat(),
        }
        MODULE.validate_manifest(self.manifest, self.policy, self.now)
        self.manifest_hash = MODULE.canonical_sha256(self.manifest)
        self.issue = {
            "number": 91,
            "html_url": "https://github.com/example/release-control/issues/91",
            "state": "closed",
            "state_reason": "completed",
            "created_at": (self.now - timedelta(minutes=50)).isoformat(),
            "closed_at": (self.now - timedelta(minutes=5)).isoformat(),
            "user": {"login": "request-author", "type": "User"},
            "body": MODULE.approval_request(self.manifest, self.manifest_hash),
        }

    def comment(
        self,
        login: str,
        role: str,
        *,
        association: str = "MEMBER",
        manifest_hash: str | None = None,
        edited: bool = False,
        evidence: str = "reviewed private immutable release evidence",
    ) -> dict[str, object]:
        created = self.now - timedelta(minutes=15)
        return {
            "body": "\n".join(
                (
                    "PUBLIC-RELEASE-APPROVED: 1",
                    "Environment: staging",
                    f"Manifest-SHA256: {manifest_hash or self.manifest_hash}",
                    f"Role: {role}",
                    "Decision: approve",
                    f"Evidence: {evidence}",
                )
            ),
            "user": {"login": login, "type": "User"},
            "author_association": association,
            "created_at": created.isoformat(),
            "updated_at": (
                created + timedelta(seconds=1) if edited else created
            ).isoformat(),
        }

    def valid_comments(self) -> list[dict[str, object]]:
        return [
            self.comment("clinical-reviewer", "clinical-safety"),
            self.comment("security-reviewer", "security"),
            self.comment("operations-reviewer", "operations"),
        ]

    def verify(self, comments=None, initiator="release-initiator"):
        return MODULE.verify_approvals(
            self.issue,
            self.valid_comments() if comments is None else comments,
            self.manifest,
            self.policy,
            initiator,
            self.now,
        )

    def test_valid_independent_authorized_approvals_pass(self) -> None:
        report = self.verify()
        self.assertEqual("verified", report["result"])
        self.assertEqual(
            ["clinical-safety", "operations", "security"], report["approvedRoles"]
        )
        self.assertEqual(
            self.manifest["releaseSetManifestSha256"],
            report["releaseSetManifestSha256"],
        )
        self.assertEqual(
            self.manifest["combinedIdentitySha256"],
            report["combinedIdentitySha256"],
        )

    def test_self_declared_role_is_not_authorization(self) -> None:
        comments = [
            self.comment("clinical-reviewer", "clinical-safety"),
            self.comment("unassigned-member", "security"),
            self.comment("operations-reviewer", "operations"),
        ]
        self.assertEqual("unverified", self.verify(comments)["result"])

    def test_issue_author_and_dispatcher_cannot_approve(self) -> None:
        self.issue["user"] = {"login": "security-reviewer", "type": "User"}
        self.assertEqual("unverified", self.verify()["result"])
        self.issue["user"] = {"login": "request-author", "type": "User"}
        self.assertEqual(
            "unverified", self.verify(initiator="operations-reviewer")["result"]
        )

    def test_duplicate_person_cannot_satisfy_both_roles(self) -> None:
        self.policy["roleApprovers"]["operations"] = ["security-reviewer"]
        comments = [
            self.comment("clinical-reviewer", "clinical-safety"),
            self.comment("security-reviewer", "security"),
            self.comment("security-reviewer", "operations"),
        ]
        self.assertEqual("unverified", self.verify(comments)["result"])

    def test_edited_untrusted_bot_and_placeholder_comments_fail(self) -> None:
        variants = []
        edited = self.comment("security-reviewer", "security", edited=True)
        variants.append(edited)
        untrusted = self.comment(
            "security-reviewer", "security", association="CONTRIBUTOR"
        )
        variants.append(untrusted)
        bot = self.comment("security-reviewer", "security")
        bot["user"]["type"] = "Bot"
        variants.append(bot)
        variants.append(
            self.comment("security-reviewer", "security", evidence="TODO review this")
        )
        for invalid in variants:
            with self.subTest(comment=invalid):
                self.assertEqual(
                    "unverified",
                    self.verify(
                        [
                            self.comment("clinical-reviewer", "clinical-safety"),
                            invalid,
                            self.comment("operations-reviewer", "operations"),
                        ]
                    )["result"],
                )

    def test_wrong_manifest_hash_and_open_issue_fail(self) -> None:
        comments = [
            self.comment("clinical-reviewer", "clinical-safety"),
            self.comment("security-reviewer", "security", manifest_hash="f" * 64),
            self.comment("operations-reviewer", "operations"),
        ]
        self.assertEqual("unverified", self.verify(comments)["result"])
        self.issue["state"] = "open"
        self.issue["state_reason"] = None
        self.assertEqual("unverified", self.verify()["result"])

    def test_extra_public_issue_or_evidence_content_fails(self) -> None:
        self.issue["body"] += "\nInternal-Reference: must-not-be-public"
        self.assertEqual("unverified", self.verify()["result"])
        self.issue["body"] = MODULE.approval_request(self.manifest, self.manifest_hash)
        comments = self.valid_comments()
        comments[0] = self.comment(
            "clinical-reviewer", "clinical-safety", evidence="reviewed ticket CLIN-123"
        )
        self.assertEqual("unverified", self.verify(comments)["result"])

    def test_comment_after_closure_fails(self) -> None:
        late = self.comment("security-reviewer", "security")
        late_time = self.now - timedelta(minutes=1)
        late["created_at"] = late_time.isoformat()
        late["updated_at"] = late_time.isoformat()
        self.assertEqual(
            "unverified",
            self.verify(
                [
                    self.comment("clinical-reviewer", "clinical-safety"),
                    late,
                    self.comment("operations-reviewer", "operations"),
                ]
            )["result"],
        )

    def test_manifest_schema_and_window_fail_closed(self) -> None:
        bad = dict(self.manifest)
        bad["unexpected"] = True
        with self.assertRaisesRegex(MODULE.VerificationError, "keys"):
            MODULE.validate_manifest(bad, self.policy, self.now)
        bad = dict(self.manifest)
        bad["expiresAt"] = (self.now + timedelta(hours=25)).isoformat()
        with self.assertRaisesRegex(MODULE.VerificationError, "window"):
            MODULE.validate_manifest(bad, self.policy, self.now)

    def test_manifest_authenticity_mismatch_and_cross_request_reuse_fail(self) -> None:
        for field in ("releaseSetManifestSha256", "combinedIdentitySha256"):
            with self.subTest(field=field):
                bad = dict(self.manifest)
                bad[field] = "0" * 64
                with self.assertRaisesRegex(
                    MODULE.VerificationError, "canonical authenticity request"
                ):
                    MODULE.validate_manifest(bad, self.policy, self.now)

        reused = dict(self.manifest)
        reused["releaseSetManifestSha256"] = "3" * 64
        reused["combinedIdentitySha256"] = "4" * 64
        with self.assertRaisesRegex(
            MODULE.VerificationError, "canonical authenticity request"
        ):
            MODULE.validate_manifest(reused, self.policy, self.now)

    def test_release_schema_locks_exact_authenticity_bindings(self) -> None:
        schema = json.loads(
            (MODULE_PATH.parents[1] / "schemas" / "release-manifest.schema.json")
            .read_text(encoding="utf-8")
        )
        for field in ("releaseSetManifestSha256", "combinedIdentitySha256"):
            with self.subTest(field=field):
                self.assertIn(field, schema["required"])
                definition = schema["properties"][field]
                self.assertEqual("^[0-9a-f]{64}$", definition["pattern"])
                self.assertEqual(
                    MODULE.verify_authenticity.EXPECTED_REQUEST[field],
                    definition["const"],
                )

    def test_bootstrap_and_role_overlap_fail_closed(self) -> None:
        bad = {
            "schemaVersion": 1,
            "bootstrapComplete": False,
            "defaultBranch": "main",
            "maximumApprovalHours": 24,
            "authenticity": {
                "signingConfigured": False,
                "expectedCertificateIdentity": "REPLACE_WITH_EXACT_PUBLIC_REPOSITORY_WORKFLOW_IDENTITY",
                "certificateOidcIssuer": "https://token.actions.githubusercontent.com",
            },
            "roleApprovers": {
                "clinical-safety": [],
                "security": [],
                "operations": [],
            },
        }
        with self.assertRaisesRegex(MODULE.VerificationError, "not complete"):
            MODULE.validate_policy(bad)
        bad["bootstrapComplete"] = True
        bad["authenticity"] = dict(self.policy["authenticity"])
        bad["roleApprovers"] = {
            "clinical-safety": ["clinical-reviewer"],
            "security": ["same-person"],
            "operations": ["same-person"],
        }
        with self.assertRaisesRegex(MODULE.VerificationError, "multiple"):
            MODULE.validate_policy(bad)

    def test_authenticity_policy_semantics_fail_closed(self) -> None:
        variants = (
            {
                "signingConfigured": "true",
                "expectedCertificateIdentity": "REPLACE_WITH_EXACT_PUBLIC_REPOSITORY_WORKFLOW_IDENTITY",
                "certificateOidcIssuer": "https://token.actions.githubusercontent.com",
            },
            {
                "signingConfigured": True,
                "expectedCertificateIdentity": (
                    "https://github.com/example/*/.github/workflows/"
                    "sign-authenticity-request.yml@refs/heads/main"
                ),
                "certificateOidcIssuer": "https://token.actions.githubusercontent.com",
            },
            {
                "signingConfigured": True,
                "expectedCertificateIdentity": (
                    "https://github.com/example/release-control/.github/workflows/"
                    "sign-authenticity-request.yml@refs/heads/main"
                ),
                "certificateOidcIssuer": "https://issuer.example.invalid",
            },
        )
        for authenticity in variants:
            with self.subTest(authenticity=authenticity):
                policy = dict(self.policy)
                policy["authenticity"] = authenticity
                with self.assertRaisesRegex(
                    MODULE.VerificationError, "authenticity settings"
                ):
                    MODULE.validate_policy(policy)

    def test_production_requires_exact_staging_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            releases = root / "releases"
            releases.mkdir()
            staging_path = releases / f"{self.manifest['releaseId']}.json"
            staging_path.write_text(json.dumps(self.manifest), encoding="utf-8")
            prod = dict(self.manifest)
            prod["releaseId"] = "rel-20260720t113000z-f6e5d4c3b2a1"
            prod["environment"] = "prod"
            prod["approvalIssue"] = 92
            prod["stagingManifestSha256"] = self.manifest_hash
            MODULE.validate_production_promotion(prod, root, self.policy, self.now)
            prod["artifacts"] = dict(prod["artifacts"])
            prod["artifacts"]["apiSha256"] = "0" * 64
            with self.assertRaisesRegex(MODULE.VerificationError, "differ"):
                MODULE.validate_production_promotion(prod, root, self.policy, self.now)

    def test_historical_staging_expiry_does_not_break_bound_promotion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            releases = root / "releases"
            releases.mkdir()
            historical = dict(self.manifest)
            historical["createdAt"] = (self.now - timedelta(hours=4)).isoformat()
            historical["expiresAt"] = (self.now - timedelta(hours=1)).isoformat()
            staging_hash = MODULE.canonical_sha256(historical)
            (releases / f"{historical['releaseId']}.json").write_text(
                json.dumps(historical), encoding="utf-8"
            )
            prod = dict(self.manifest)
            prod["releaseId"] = "rel-20260720t113000z-f6e5d4c3b2a1"
            prod["environment"] = "prod"
            prod["approvalIssue"] = 92
            prod["stagingManifestSha256"] = staging_hash
            MODULE.validate_production_promotion(prod, root, self.policy, self.now)

    def test_manifest_path_rejects_wrong_name_and_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            releases = root / "releases"
            releases.mkdir()
            path = releases / "wrong.json"
            path.write_text(json.dumps(self.manifest), encoding="utf-8")
            with self.assertRaisesRegex(MODULE.VerificationError, "filename"):
                MODULE.validate_manifest_path(path, root, self.manifest)
            target = releases / f"{self.manifest['releaseId']}.json"
            target.symlink_to(path)
            with self.assertRaisesRegex(MODULE.VerificationError, "non-symlink"):
                MODULE.load_json(target)

    def test_report_omits_people_issue_body_and_evidence_text(self) -> None:
        serialized = json.dumps(self.verify())
        for forbidden in (
            "security-reviewer",
            "clinical-reviewer",
            "operations-reviewer",
            "request-author",
            "release-initiator",
            "reviewed private immutable release evidence",
            "https://github.com",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_report_write_is_atomic_private_and_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            MODULE.write_report(path, {"result": "verified"})
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
            self.assertEqual("verified", json.loads(path.read_text())["result"])
            target = Path(directory) / "target.json"
            target.write_text("{}")
            link = Path(directory) / "link.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(MODULE.VerificationError, "symlink"):
                MODULE.write_report(link, {"result": "verified"})

    def test_request_round_trip_and_comment_pagination(self) -> None:
        parsed = MODULE.parse_request(self.issue["body"])
        self.assertEqual(self.manifest_hash, parsed["manifestSha256"])
        comments = self.valid_comments()
        self.assertEqual(
            comments,
            MODULE.flatten_comments([[comments[0]], [comments[1]], [comments[2]]]),
        )
        with self.assertRaisesRegex(MODULE.VerificationError, "invalid"):
            MODULE.flatten_comments({"items": []})

    def test_documented_direct_command_does_not_create_bytecode_cache(self) -> None:
        readme = MODULE_PATH.parents[1] / "README.md"
        self.assertIn(
            "python3 scripts/verify_release.py --help",
            readme.read_text(encoding="utf-8"),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scripts = root / "scripts"
            scripts.mkdir()
            shutil.copy2(MODULE_PATH, scripts / "verify_release.py")
            shutil.copy2(
                MODULE_PATH.with_name("verify_authenticity.py"),
                scripts / "verify_authenticity.py",
            )
            result = subprocess.run(
                [sys.executable, "scripts/verify_release.py", "--help"],
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertFalse((scripts / "__pycache__").exists())


if __name__ == "__main__":
    unittest.main()
