#!/usr/bin/env python3

import base64
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
PUBLISHED_SOURCE_COMMIT = "16018f5842b4815e283d860b66d8614e0ce13e0a"
PUBLISHED_PYTHON_PATHS = frozenset(
    {
        "scripts/test_verify_authenticity.py",
        "scripts/test_verify_release.py",
        "scripts/test_verify_repository_policy.py",
        "scripts/verify_authenticity.py",
        "scripts/verify_release.py",
        "scripts/verify_repository_policy.py",
    }
)


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

    def load_trust_manifest(self, root: Path) -> dict[str, object]:
        return json.loads((root / MODULE.TRUST_MANIFEST).read_text(encoding="utf-8"))

    def write_trust_manifest(self, root: Path, document: dict[str, object]) -> None:
        (root / MODULE.TRUST_MANIFEST).write_bytes(MODULE.canonical_json_bytes(document))

    def stage_complete_bundle(self, root: Path, marker: bytes = b"# reviewed next bytes\n") -> None:
        document = self.load_trust_manifest(root)
        staged: dict[str, str] = {}
        for relative in sorted(MODULE.TRUSTED_CODE_PATHS):
            source = root / relative
            target = root / MODULE.STAGED_ROOT / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes() + marker)
            target.chmod(0o644)
            staged[relative] = hashlib.sha256(target.read_bytes()).hexdigest()
        document["staged"] = staged
        self.write_trust_manifest(root, document)

    def promote_staged_bundle(self, root: Path) -> None:
        document = self.load_trust_manifest(root)
        staged = document["staged"]
        self.assertIsInstance(staged, dict)
        for relative in sorted(MODULE.TRUSTED_CODE_PATHS):
            (root / relative).write_bytes((root / MODULE.STAGED_ROOT / relative).read_bytes())
        document["active"] = staged
        self.write_trust_manifest(root, document)

    def cleanup_staged_bundle(self, root: Path) -> None:
        document = self.load_trust_manifest(root)
        document.pop("staged")
        shutil.rmtree(root / "trust")
        self.write_trust_manifest(root, document)

    def test_current_scaffold_passes(self) -> None:
        result = MODULE.validate_repository(SOURCE_ROOT)
        self.assertGreater(result["files"], 8)

    def test_published_workflow_and_legacy_positional_cli_remain_bootstrap_compatible(
        self,
    ) -> None:
        workflow = SOURCE_ROOT / ".github" / "workflows" / "validate-control.yml"
        self.assertEqual(
            "12c6efc77b7cec8964ea39c7ee845607027811ca8a9383892ffbb119a6d56638",
            hashlib.sha256(workflow.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            2,
            workflow.read_text(encoding="utf-8").count(
                'run: python3 scripts/verify_repository_policy.py "$CANDIDATE_ROOT"'
            ),
        )

        with tempfile.TemporaryDirectory() as directory:
            candidate = self.copy_repository(directory)
            relative = "scripts/verify_release.py"
            trusted_file = candidate / relative
            trusted_file.write_bytes(trusted_file.read_bytes() + b"# direct mutation\n")
            document = self.load_trust_manifest(candidate)
            document["active"][relative] = hashlib.sha256(
                trusted_file.read_bytes()
            ).hexdigest()
            self.write_trust_manifest(candidate, document)
            result = subprocess.run(
                [sys.executable, str(MODULE_PATH), str(candidate)],
                cwd=MODULE_PATH.parents[1],
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(1, result.returncode)
            self.assertIn("trusted-code transition", result.stderr)

    def test_published_old_base_accepts_first_hardening_candidate(self) -> None:
        self.assertFalse((SOURCE_ROOT / "trust").exists())
        fixture_path = SOURCE_ROOT / "docs" / "published-python-controls.json"
        raw = fixture_path.read_bytes()
        fixture = json.loads(raw)
        self.assertEqual(MODULE.canonical_json_bytes(fixture), raw)
        self.assertEqual({"formatVersion", "sourceCommit", "files"}, set(fixture))
        self.assertEqual(1, fixture["formatVersion"])
        self.assertEqual(PUBLISHED_SOURCE_COMMIT, fixture["sourceCommit"])
        self.assertEqual(PUBLISHED_PYTHON_PATHS, set(fixture["files"]))

        with tempfile.TemporaryDirectory() as directory:
            published_root = Path(directory) / "published-control"
            for relative, record in fixture["files"].items():
                self.assertEqual({"base64", "sha256"}, set(record))
                content = base64.b64decode(record["base64"], validate=True)
                self.assertEqual(record["sha256"], hashlib.sha256(content).hexdigest())
                target = published_root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
                target.chmod(0o644)
            (published_root / "schemas").mkdir()
            for relative in ("README.md", "schemas/release-manifest.schema.json"):
                target = published_root / relative
                target.write_bytes((SOURCE_ROOT / relative).read_bytes())
                target.chmod(0o644)

            environment = {
                **os.environ,
                "PYTHONDONTWRITEBYTECODE": "1",
                "PUBLIC_REPOSITORY_UNDER_TEST": str(SOURCE_ROOT),
                "CANDIDATE_ROOT": str(SOURCE_ROOT),
            }
            commands = (
                [sys.executable, "scripts/test_verify_release.py"],
                [sys.executable, "scripts/test_verify_authenticity.py"],
                [sys.executable, "scripts/test_verify_repository_policy.py"],
                [
                    sys.executable,
                    "scripts/verify_repository_policy.py",
                    str(SOURCE_ROOT),
                ],
            )
            for command in commands:
                with self.subTest(command=command):
                    result = subprocess.run(
                        command,
                        cwd=published_root,
                        env=environment,
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(
                        0,
                        result.returncode,
                        result.stdout + result.stderr,
                    )

    def test_manifest_covers_all_workflows_verifiers_helpers_and_tests(self) -> None:
        document = MODULE.validate_trust_state(SOURCE_ROOT)
        self.assertEqual(MODULE.TRUSTED_CODE_PATHS, set(document["active"]))
        self.assertEqual(10, len(document["active"]))
        self.assertEqual(3, sum(path.startswith(".github/workflows/") for path in document["active"]))
        self.assertEqual(6, sum(path.startswith("scripts/") for path in document["active"]))
        self.assertIn("docs/published-python-controls.json", document["active"])

    def test_valid_unchanged_stage_promote_and_cleanup_transitions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = self.copy_repository(str(Path(directory) / "base"))
            unchanged = self.copy_repository(str(Path(directory) / "unchanged"))
            self.assertEqual("unchanged", MODULE.validate_trusted_code_transition(base, unchanged))

            staged = self.copy_repository(str(Path(directory) / "staged"))
            self.stage_complete_bundle(staged)
            self.assertEqual("stage", MODULE.validate_trusted_code_transition(base, staged))

            promoted = Path(directory) / "promoted" / "release-control"
            promoted.parent.mkdir()
            shutil.copytree(staged, promoted)
            self.promote_staged_bundle(promoted)
            self.assertEqual("promote", MODULE.validate_trusted_code_transition(staged, promoted))
            MODULE.validate_repository(promoted, staged)

            cleaned = Path(directory) / "cleaned" / "release-control"
            cleaned.parent.mkdir()
            shutil.copytree(promoted, cleaned)
            self.cleanup_staged_bundle(cleaned)
            self.assertEqual("cleanup", MODULE.validate_trusted_code_transition(promoted, cleaned))

    def test_direct_trusted_code_mutation_and_mapping_rewrite_fail(self) -> None:
        for relative in sorted(MODULE.TRUSTED_CODE_PATHS):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as directory:
                base = self.copy_repository(str(Path(directory) / "base"))
                candidate = self.copy_repository(str(Path(directory) / "candidate"))
                path = candidate / relative
                path.write_bytes(path.read_bytes() + b"# direct mutation\n")
                document = self.load_trust_manifest(candidate)
                document["active"][relative] = hashlib.sha256(path.read_bytes()).hexdigest()
                self.write_trust_manifest(candidate, document)
                with self.assertRaisesRegex(MODULE.PolicyError, "trusted-code transition"):
                    MODULE.validate_repository(candidate, base)

    def test_active_trusted_code_rejects_executable_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            target = root / "scripts" / "verify_release.py"
            target.chmod(0o755)
            with self.assertRaisesRegex(MODULE.PolicyError, "executable trusted-code"):
                MODULE.validate_trust_state(root)

    def test_exact_promotion_rejects_executable_active_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            staged = self.copy_repository(str(Path(directory) / "staged"))
            self.stage_complete_bundle(staged)
            promoted = Path(directory) / "promoted" / "release-control"
            promoted.parent.mkdir()
            shutil.copytree(staged, promoted)
            self.promote_staged_bundle(promoted)
            (promoted / "scripts" / "verify_release.py").chmod(0o755)
            with self.assertRaisesRegex(MODULE.PolicyError, "executable trusted-code"):
                MODULE.validate_trusted_code_transition(staged, promoted)

    def test_simultaneous_stage_and_promote_and_partial_promotion_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = self.copy_repository(str(Path(directory) / "base"))
            simultaneous = self.copy_repository(str(Path(directory) / "simultaneous"))
            self.stage_complete_bundle(simultaneous)
            self.promote_staged_bundle(simultaneous)
            with self.assertRaisesRegex(MODULE.PolicyError, "trusted-code transition"):
                MODULE.validate_trusted_code_transition(base, simultaneous)

            staged = self.copy_repository(str(Path(directory) / "staged"))
            self.stage_complete_bundle(staged)
            partial = Path(directory) / "partial" / "release-control"
            partial.parent.mkdir()
            shutil.copytree(staged, partial)
            document = self.load_trust_manifest(partial)
            first = sorted(MODULE.TRUSTED_CODE_PATHS)[0]
            (partial / first).write_bytes((partial / MODULE.STAGED_ROOT / first).read_bytes())
            document["active"][first] = document["staged"][first]
            self.write_trust_manifest(partial, document)
            with self.assertRaisesRegex(MODULE.PolicyError, "trusted-code transition"):
                MODULE.validate_trusted_code_transition(staged, partial)

    def test_malformed_unknown_traversal_and_incomplete_mappings_fail(self) -> None:
        variants = (
            lambda document: document.update({"unknown": True}),
            lambda document: document["active"].update({"../escape.py": "a" * 64}),
            lambda document: document["active"].update({"scripts/unknown.py": "a" * 64}),
            lambda document: document["active"].update({next(iter(document["active"])): "bad"}),
            lambda document: document["active"].pop(next(iter(document["active"]))),
        )
        for mutate in variants:
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as directory:
                root = self.copy_repository(directory)
                document = self.load_trust_manifest(root)
                mutate(document)
                self.write_trust_manifest(root, document)
                with self.assertRaises(MODULE.PolicyError):
                    MODULE.validate_trust_state(root)

    def test_staged_tree_rejects_symlink_extra_and_executable_files(self) -> None:
        for mutation in ("symlink", "extra", "executable"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = self.copy_repository(directory)
                self.stage_complete_bundle(root)
                target = root / MODULE.STAGED_ROOT / sorted(MODULE.TRUSTED_CODE_PATHS)[0]
                if mutation == "symlink":
                    target.unlink()
                    target.symlink_to(root / sorted(MODULE.TRUSTED_CODE_PATHS)[0])
                elif mutation == "extra":
                    extra = root / MODULE.STAGED_ROOT / "scripts/extra.py"
                    extra.write_text("raise SystemExit(1)\n", encoding="utf-8")
                else:
                    target.chmod(0o755)
                with self.assertRaisesRegex(MODULE.PolicyError, "symlink|exactly|executable"):
                    MODULE.validate_trust_state(root)

    def test_rotation_process_and_direct_main_prohibition_are_documented(self) -> None:
        readme = (SOURCE_ROOT / "README.md").read_text(encoding="utf-8")
        bootstrap = (SOURCE_ROOT / "docs" / "bootstrap.md").read_text(
            encoding="utf-8"
        )
        for stage in ("**Stage:**", "**Promote:**", "**Cleanup:**"):
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
                    "trusted-code byte digest|may execute only trusted verifier",
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
            self.stage_complete_bundle(
                candidate,
                b'raise RuntimeError("staged candidate code must remain inert")\n',
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(MODULE_PATH),
                    "--trusted-root",
                    str(MODULE_PATH.parents[1]),
                    "--candidate-root",
                    str(candidate),
                ],
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
