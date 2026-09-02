#!/usr/bin/env python3

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


sys.dont_write_bytecode = True
MODULE_PATH = Path(__file__).with_name("verify_repository_policy.py")
SPEC = importlib.util.spec_from_file_location("verify_repository_policy", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
SOURCE_ROOT = Path(
    os.environ.get("PUBLIC_REPOSITORY_UNDER_TEST", MODULE_PATH.parents[1])
).resolve()


class PublicRepositoryPolicyTests(unittest.TestCase):
    def copy_repository(self, directory: str) -> Path:
        root = Path(directory) / "release-control"
        shutil.copytree(SOURCE_ROOT, root)
        return root

    def mutate_workflow(self, root: Path, old: str, new: str) -> None:
        self.mutate_named_workflow(root, "deploy-approved-release.yml", old, new)

    def mutate_named_workflow(
        self, root: Path, name: str, old: str, new: str
    ) -> None:
        path = root / ".github" / "workflows" / name
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text)
        path.write_text(text.replace(old, new, 1), encoding="utf-8")

    def mutate_signing_workflow(self, root: Path, old: str, new: str) -> None:
        self.mutate_named_workflow(root, "sign-authenticity-request.yml", old, new)

    def test_current_scaffold_passes(self) -> None:
        result = MODULE.validate_repository(SOURCE_ROOT)
        self.assertGreater(result["files"], 8)

    def test_current_workflows_match_exact_approved_byte_digests(self) -> None:
        workflows = SOURCE_ROOT / ".github" / "workflows"
        MODULE.validate_workflow_hash_allowlist(MODULE.WORKFLOW_SHA256_ALLOWLIST)
        for name, expected in MODULE.WORKFLOW_SHA256_ALLOWLIST.items():
            with self.subTest(name=name):
                actual = hashlib.sha256((workflows / name).read_bytes()).hexdigest()
                self.assertIn(actual, expected)
                self.assertEqual(1, len(expected))

    def test_three_pr_workflow_hash_rotation_is_permitted_by_trusted_base(self) -> None:
        workflow = SOURCE_ROOT / ".github" / "workflows" / "validate-control.yml"
        old_hash = hashlib.sha256(workflow.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            future = Path(directory) / workflow.name
            future.write_bytes(workflow.read_bytes().replace(
                b"name: Validate public release control",
                b"name: Validate public release control rotated",
                1,
            ))
            future_hash = hashlib.sha256(future.read_bytes()).hexdigest()
            base = dict(MODULE.WORKFLOW_SHA256_ALLOWLIST)

            pr1 = {**base, workflow.name: frozenset({old_hash, future_hash})}
            MODULE.validate_workflow_byte_contract(workflow, pr1)

            MODULE.validate_workflow_byte_contract(future, pr1)

            pr3 = {**base, workflow.name: frozenset({future_hash})}
            MODULE.validate_workflow_byte_contract(future, pr3)
            with self.assertRaisesRegex(MODULE.PolicyError, "not approved"):
                MODULE.validate_workflow_byte_contract(workflow, pr3)

    def test_workflow_hash_rotation_is_bounded_and_cannot_skip_pr1(self) -> None:
        workflow = SOURCE_ROOT / ".github" / "workflows" / "validate-control.yml"
        current_hash = hashlib.sha256(workflow.read_bytes()).hexdigest()
        base = dict(MODULE.WORKFLOW_SHA256_ALLOWLIST)
        invalid_sets = (
            frozenset(),
            frozenset({current_hash, "1" * 64, "2" * 64}),
            frozenset({"NOT-A-DIGEST"}),
        )
        for digests in invalid_sets:
            with self.subTest(digests=digests):
                invalid = {**base, workflow.name: digests}
                with self.assertRaisesRegex(MODULE.PolicyError, "allowlist"):
                    MODULE.validate_workflow_byte_contract(workflow, invalid)

        future_only = {**base, workflow.name: frozenset({"f" * 64})}
        with self.assertRaisesRegex(MODULE.PolicyError, "not approved"):
            MODULE.validate_workflow_byte_contract(workflow, future_only)

    def test_rotation_process_and_direct_main_prohibition_are_documented(self) -> None:
        readme = (SOURCE_ROOT / "README.md").read_text(encoding="utf-8")
        bootstrap = (SOURCE_ROOT / "docs" / "bootstrap.md").read_text(
            encoding="utf-8"
        )
        for stage in ("**PR1:**", "**PR2:**", "**PR3:**"):
            self.assertIn(stage, readme)
        self.assertIn("A direct-main change", readme)
        self.assertIn("disable direct pushes to `main`", bootstrap)
        validation = (
            SOURCE_ROOT / ".github" / "workflows" / "validate-control.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("pull_request_target:", validation)
        self.assertNotIn("\n  pull_request:\n", validation)

    def test_exact_byte_contract_rejects_parser_and_control_flow_bypasses(self) -> None:
        mutations = (
            (
                "deploy-approved-release.yml",
                "          set -euo pipefail\n"
                "          git ls-files --error-unmatch -- \\",
                "          set -euo pipefail\n"
                "          exit 0\n"
                "          git ls-files --error-unmatch -- \\",
            ),
            (
                "validate-control.yml",
                '        run: python3 scripts/verify_repository_policy.py "$CANDIDATE_ROOT"',
                '        run: python3 scripts/verify_repository_policy.py "$CANDIDATE_ROOT"\n'
                "        \"r\\u0075n\": exit 0",
            ),
            (
                "validate-control.yml",
                '        run: python3 scripts/verify_repository_policy.py "$CANDIDATE_ROOT"',
                '        run: python3 scripts/verify_repository_policy.py "$CANDIDATE_ROOT"\n'
                "        run: exit 0",
            ),
            (
                "deploy-approved-release.yml",
                "          set -euo pipefail\n"
                "          git ls-files --error-unmatch -- \\",
                "          set -euo pipefail; trap 'exit 0' ERR\n"
                "          git ls-files --error-unmatch -- \\",
            ),
        )
        for name, old, new in mutations:
            with (
                self.subTest(name=name, mutation=new),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = self.copy_repository(directory)
                self.mutate_named_workflow(root, name, old, new)
                with self.assertRaisesRegex(
                    MODULE.PolicyError,
                    "workflow byte digest|may execute only trusted verifier",
                ):
                    MODULE.validate_repository(root)

    def test_application_source_and_unknown_root_file_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            source = root / "src"
            source.mkdir()
            (source / "Patient.cs").write_text("public class Patient {}")
            with self.assertRaisesRegex(MODULE.PolicyError, "not allowlisted"):
                MODULE.validate_repository(root)
            shutil.rmtree(source)
            (root / "notes.txt").write_text("internal")
            with self.assertRaisesRegex(MODULE.PolicyError, "not allowlisted"):
                MODULE.validate_repository(root)

    def test_symlink_and_oversized_file_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            (root / "docs" / "linked.md").symlink_to(root / "README.md")
            with self.assertRaisesRegex(MODULE.PolicyError, "symlink"):
                MODULE.validate_repository(root)
            (root / "docs" / "linked.md").unlink()
            (root / "docs" / "large.md").write_text(
                "x" * (MODULE.MAX_FILE_BYTES + 1)
            )
            with self.assertRaisesRegex(MODULE.PolicyError, "size"):
                MODULE.validate_repository(root)

    def test_secret_private_key_and_private_address_fail(self) -> None:
        payloads = (
            "gh" + "p_abcdefghijklmnopqrstuvwxyz123456",
            "-----BEGIN " + "PRIVATE KEY-----\nnot-a-real-key",
            "private target " + "10." + "2.3.4",
        )
        for index, payload in enumerate(payloads):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                root = self.copy_repository(directory)
                (root / "docs" / "leak.md").write_text(payload)
                with self.assertRaisesRegex(MODULE.PolicyError, "possible"):
                    MODULE.validate_repository(root)

    def test_sensitive_filename_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            (root / "docs" / "credentials.json").write_text("{}")
            with self.assertRaisesRegex(MODULE.PolicyError, "filename"):
                MODULE.validate_repository(root)

    def test_unpinned_action_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            self.mutate_workflow(
                root,
                "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
                "actions/checkout@v4",
            )
            with self.assertRaisesRegex(MODULE.PolicyError, "full lowercase"):
                MODULE.validate_repository(root)

    def test_local_docker_unknown_and_extra_actions_fail(self) -> None:
        mutations = (
            (
                "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
                "docker://alpine:3.20",
            ),
            (
                "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
                "./.github/actions/local",
            ),
            (
                "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
                "attacker/action@" + "a" * 40,
            ),
            (
                "uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
                "uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5\n"
                "      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
            ),
        )
        for old, new in mutations:
            with self.subTest(new=new), tempfile.TemporaryDirectory() as directory:
                root = self.copy_repository(directory)
                self.mutate_workflow(root, old, new)
                with self.assertRaisesRegex(
                    MODULE.PolicyError, "uses|action.*allowlist"
                ):
                    MODULE.validate_repository(root)

    def test_broad_and_unexpected_job_permissions_fail(self) -> None:
        mutations = (
            ("permissions:\n  contents: read", "permissions: write-all"),
            ("permissions:\n  contents: read", "permissions: read-all"),
            (
                "  gate:\n    if:",
                "  gate:\n    permissions: {}\n    if:",
            ),
            (
                "  gate:\n    if:",
                "  gate:\n    permissions: write-all\n    if:",
            ),
            (
                "    timeout-minutes: 10\n    outputs:",
                "    timeout-minutes: 10\n    permissions:\n      contents: read\n    outputs:",
            ),
            (
                "  gate:\n    if:",
                "  gate: { permissions: write-all }\n  replacement-gate:\n    if:",
            ),
        )
        for old, new in mutations:
            with self.subTest(new=new), tempfile.TemporaryDirectory() as directory:
                root = self.copy_repository(directory)
                self.mutate_workflow(root, old, new)
                with self.assertRaisesRegex(MODULE.PolicyError, "permissions"):
                    MODULE.validate_repository(root)

    def test_pr_validation_uses_only_trusted_base_code_against_inert_candidate(self) -> None:
        validation = (
            SOURCE_ROOT / ".github" / "workflows" / "validate-control.yml"
        ).read_text(encoding="utf-8")
        MODULE.validate_control_validation_workflow(validation)
        self.assertNotIn("working-directory: candidate", validation)
        self.assertNotIn("candidate/scripts", validation)
        self.assertNotIn("secrets.", validation)
        self.assertEqual(4, validation.count("persist-credentials: false"))

    def test_main_push_validation_uses_previous_trusted_verifier(self) -> None:
        validation = (
            SOURCE_ROOT / ".github" / "workflows" / "validate-control.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("ref: ${{ github.event.before }}", validation)
        self.assertEqual(1, validation.count("ref: ${{ github.sha }}"))
        self.assertIn(
            "github.event.before != '0000000000000000000000000000000000000000'",
            validation,
        )
        self.assertIn("path: trusted", validation)
        self.assertIn("path: candidate", validation)

    def test_trusted_verifier_never_imports_or_executes_candidate_scripts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = self.copy_repository(directory)
            for path in (candidate / "scripts").glob("*.py"):
                path.write_text(
                    'raise RuntimeError("candidate code must remain inert")\n',
                    encoding="utf-8",
                )
            result = subprocess.run(
                [sys.executable, str(MODULE_PATH), str(candidate)],
                cwd=MODULE_PATH.parents[1],
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, result.returncode, result.stderr)

    def test_pr_validation_trust_boundary_mutations_fail(self) -> None:
        mutations = (
            (
                "ref: ${{ github.event.pull_request.base.sha }}",
                "ref: ${{ github.event.pull_request.head.sha }}",
            ),
            (
                "repository: ${{ github.event.pull_request.head.repo.full_name }}",
                "repository: ${{ github.repository }}",
            ),
            ("path: trusted", "path: candidate"),
            ("working-directory: trusted", "working-directory: candidate"),
            (
                "run: python3 scripts/test_verify_release.py",
                "run: python3 candidate/scripts/test_verify_release.py",
            ),
            (
                'run: python3 scripts/verify_repository_policy.py "$CANDIDATE_ROOT"',
                "run: python3 scripts/verify_repository_policy.py .",
            ),
            ("persist-credentials: false", "persist-credentials: true"),
            ("permissions:\n  contents: read", "permissions:\n  contents: write"),
            (
                'PYTHONDONTWRITEBYTECODE: "1"',
                'ATTACKER_TOKEN: ${{ secrets.ATTACKER_TOKEN }}',
            ),
        )
        for old, new in mutations:
            with self.subTest(new=new), tempfile.TemporaryDirectory() as directory:
                root = self.copy_repository(directory)
                self.mutate_named_workflow(root, "validate-control.yml", old, new)
                with self.assertRaises(MODULE.PolicyError):
                    MODULE.validate_repository(root)

    def test_authenticity_request_is_required_exact_and_canonical(self) -> None:
        variants = (
            b"not-json\n",
            json.dumps(
                MODULE.verify_authenticity.EXPECTED_REQUEST, sort_keys=True
            ).encode("utf-8"),
            MODULE.verify_authenticity.canonical_bytes(
                {**MODULE.verify_authenticity.EXPECTED_REQUEST, "extra": True}
            ),
        )
        for raw in variants:
            with self.subTest(raw=raw[:20]), tempfile.TemporaryDirectory() as directory:
                root = self.copy_repository(directory)
                (root / "authenticity" / "authenticity-request.json").write_bytes(raw)
                with self.assertRaisesRegex(MODULE.PolicyError, "authenticity validation"):
                    MODULE.validate_repository(root)
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            (root / "authenticity" / "authenticity-request.json").unlink()
            with self.assertRaisesRegex(MODULE.PolicyError, "allowlist"):
                MODULE.validate_repository(root)

    def test_orphan_or_unconfigured_bundle_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            authenticity = root / "authenticity"
            (authenticity / "authenticity-request.sigstore.json").write_text(
                '{"mediaType":"test"}', encoding="utf-8"
            )
            (authenticity / "authenticity-request.json").unlink()
            with self.assertRaisesRegex(MODULE.PolicyError, "allowlist"):
                MODULE.validate_repository(root)
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            (root / "authenticity" / "authenticity-request.sigstore.json").write_text(
                '{"mediaType":"test"}', encoding="utf-8"
            )
            with self.assertRaisesRegex(MODULE.PolicyError, "not configured"):
                MODULE.validate_repository(root)

    def test_signing_workflow_privilege_upload_and_identity_weakening_fail(self) -> None:
        mutations = (
            ("contents: read", "contents: write"),
            ("persist-credentials: false", "repository: private/example"),
            (
                "${{ runner.temp }}/authenticity-request.sigstore.json",
                "${{ runner.temp }}/authenticity-request.sigstore.json\n"
                "            ${{ runner.temp }}/extra.txt",
            ),
            ("--certificate-identity \"$identity\"", "--certificate-identity-regexp '.*'"),
        )
        for old, new in mutations:
            with self.subTest(new=new), tempfile.TemporaryDirectory() as directory:
                root = self.copy_repository(directory)
                self.mutate_signing_workflow(root, old, new)
                with self.assertRaises(MODULE.PolicyError):
                    MODULE.validate_repository(root)

    def test_signing_workflow_requires_fail_closed_identity_guard(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            self.mutate_signing_workflow(
                root,
                'test "$identity" != "REPLACE_WITH_EXACT_PUBLIC_REPOSITORY_WORKFLOW_IDENTITY"',
                "true",
            )
            with self.assertRaisesRegex(MODULE.PolicyError, "required control"):
                MODULE.validate_repository(root)

    def test_unsafe_trigger_and_public_self_hosted_runner_fail(self) -> None:
        mutations = (
            ("workflow_dispatch:", "pull_request_target:"),
            ("runs-on: ubuntu-latest", "runs-on: self-hosted"),
        )
        for old, new in mutations:
            with self.subTest(new=new), tempfile.TemporaryDirectory() as directory:
                root = self.copy_repository(directory)
                self.mutate_workflow(root, old, new)
                with self.assertRaisesRegex(MODULE.PolicyError, "unsafe"):
                    MODULE.validate_repository(root)

    def test_dynamic_environment_and_gate_secret_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            self.mutate_workflow(
                root, "environment:\n      name: staging", "environment: ${{ inputs.environment }}"
            )
            with self.assertRaisesRegex(MODULE.PolicyError, "required control|static"):
                MODULE.validate_repository(root)
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            self.mutate_workflow(
                root,
                "GH_TOKEN: ${{ github.token }}",
                "GH_TOKEN: ${{ secrets.DEPLOY_SSH_PRIVATE_KEY }}",
            )
            with self.assertRaisesRegex(MODULE.PolicyError, "gate"):
                MODULE.validate_repository(root)

    def test_runtime_host_enrollment_and_unknown_secret_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            self.mutate_workflow(
                root,
                "printf '%s\\n' \"$DEPLOY_KNOWN_HOSTS\" > \"$known_hosts\"",
                "ssh-keyscan \"$DEPLOY_HOST\" > \"$known_hosts\"",
            )
            with self.assertRaisesRegex(MODULE.PolicyError, "unsafe"):
                MODULE.validate_repository(root)
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            self.mutate_workflow(
                root,
                "DEPLOY_HOST: ${{ secrets.DEPLOY_HOST }}",
                "DEPLOY_HOST: ${{ secrets.UNSCOPED_TOKEN }}",
            )
            with self.assertRaisesRegex(MODULE.PolicyError, "allowlist"):
                MODULE.validate_repository(root)

    def test_missing_static_environment_and_token_permission_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            self.mutate_workflow(
                root, "environment:\n      name: prod", "environment:\n      name: production"
            )
            with self.assertRaisesRegex(MODULE.PolicyError, "required control"):
                MODULE.validate_repository(root)
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            self.mutate_workflow(root, "permissions: {}", "permissions:\n      contents: write")
            with self.assertRaisesRegex(MODULE.PolicyError, "permissions"):
                MODULE.validate_repository(root)

    def test_deploy_authenticity_gate_cannot_be_commented_out(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            self.mutate_workflow(
                root,
                "          python3 scripts/verify_authenticity.py \\\n"
                "            --request authenticity/authenticity-request.json \\\n"
                "            --bundle authenticity/authenticity-request.sigstore.json \\\n"
                "            --policy release-control-policy.json \\\n"
                "            --cosign cosign",
                "          # python3 scripts/verify_authenticity.py \\\n"
                "          # --request authenticity/authenticity-request.json \\\n"
                "          # --bundle authenticity/authenticity-request.sigstore.json \\\n"
                "          # --policy release-control-policy.json \\\n"
                "          # --cosign cosign",
            )
            with self.assertRaisesRegex(MODULE.PolicyError, "actively verify"):
                MODULE.validate_repository(root)

    def test_deploy_manifest_report_authenticity_mismatch_controls_cannot_be_reused(self) -> None:
        mutations = (
            (
                '          test "$(jq -er \'.releaseSetManifestSha256\' "$MANIFEST_PATH")" = "$release_set_manifest_sha256"',
                "          true",
            ),
            (
                '          test "$(jq -er \'.combinedIdentitySha256\' "$report")" = "$combined_identity_sha256"',
                '          test "$(jq -er \'.combinedIdentitySha256\' "$MANIFEST_PATH")" = "$combined_identity_sha256"',
            ),
            (
                '            --release-set-manifest-sha256 "${{ needs.gate.outputs.release_set_manifest_sha256 }}" \\',
                '            --release-set-manifest-sha256 "${{ needs.gate.outputs.combined_identity_sha256 }}" \\',
            ),
        )
        for old, new in mutations:
            with self.subTest(new=new), tempfile.TemporaryDirectory() as directory:
                root = self.copy_repository(directory)
                self.mutate_workflow(root, old, new)
                with self.assertRaisesRegex(
                    MODULE.PolicyError,
                    "authenticity request|authenticity bindings|byte digest",
                ):
                    MODULE.validate_repository(root)

    def test_manifest_is_rejected_before_bootstrap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            (root / "releases" / "rel-20260720t110000z-a1b2c3d4e5f6.json").write_text(
                "{}", encoding="utf-8"
            )
            with self.assertRaisesRegex(MODULE.PolicyError, "before bootstrap"):
                MODULE.validate_repository(root)

    def test_completed_bootstrap_without_bundle_fails_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            policy_path = root / "release-control-policy.json"
            policy = json.loads(policy_path.read_text(encoding="utf-8"))
            policy["bootstrapComplete"] = True
            policy["authenticity"] = {
                "signingConfigured": True,
                "expectedCertificateIdentity": (
                    "https://github.com/example/release-control/.github/workflows/"
                    "sign-authenticity-request.yml@refs/heads/main"
                ),
                "certificateOidcIssuer": MODULE.verify_authenticity.EXPECTED_ISSUER,
            }
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            with self.assertRaisesRegex(MODULE.PolicyError, "requires a committed"):
                MODULE.validate_repository(root)

    def test_configured_signing_before_bootstrap_allows_missing_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            policy_path = root / "release-control-policy.json"
            policy = json.loads(policy_path.read_text(encoding="utf-8"))
            policy["authenticity"] = {
                "signingConfigured": True,
                "expectedCertificateIdentity": (
                    "https://github.com/example/release-control/.github/workflows/"
                    "sign-authenticity-request.yml@refs/heads/main"
                ),
                "certificateOidcIssuer": MODULE.verify_authenticity.EXPECTED_ISSUER,
            }
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            MODULE.validate_repository(root)

    def test_configured_repository_validates_every_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            policy = {
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
            (root / "release-control-policy.json").write_text(json.dumps(policy))
            (root / "authenticity" / "authenticity-request.sigstore.json").write_text(
                '{"mediaType":"test"}', encoding="utf-8"
            )
            release_id = "rel-20260720t110000z-a1b2c3d4e5f6"
            manifest = {
                "schemaVersion": 1,
                "releaseId": release_id,
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
                "createdAt": "2026-07-19T10:00:00+00:00",
                "expiresAt": "2026-07-19T12:00:00+00:00",
            }
            path = root / "releases" / f"{release_id}.json"
            path.write_text(json.dumps(manifest))
            with mock.patch.object(MODULE.verify_authenticity, "verify_bundle"):
                MODULE.validate_repository(root)
            manifest["unexpected"] = True
            path.write_text(json.dumps(manifest))
            with mock.patch.object(MODULE.verify_authenticity, "verify_bundle"):
                with self.assertRaisesRegex(MODULE.PolicyError, "manifest validation"):
                    MODULE.validate_repository(root)


if __name__ == "__main__":
    unittest.main()
