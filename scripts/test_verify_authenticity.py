#!/usr/bin/env python3

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


sys.dont_write_bytecode = True
MODULE_PATH = Path(__file__).with_name("verify_authenticity.py")
SPEC = importlib.util.spec_from_file_location("verify_authenticity", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
SOURCE_ROOT = Path(
    os.environ.get("PUBLIC_REPOSITORY_UNDER_TEST", MODULE_PATH.parents[1])
).resolve()


class AuthenticityVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.configured_policy = {
            "signingConfigured": True,
            "expectedCertificateIdentity": MODULE.EXPECTED_CERTIFICATE_IDENTITY,
            "certificateOidcIssuer": "https://token.actions.githubusercontent.com",
        }

    def write_request(self, root: Path, raw: bytes | None = None) -> Path:
        path = root / "request.json"
        path.write_bytes(raw or MODULE.canonical_bytes(MODULE.EXPECTED_REQUEST))
        return path

    def test_checked_in_request_is_exact_and_canonical(self) -> None:
        request = SOURCE_ROOT / "authenticity" / "authenticity-request.json"
        self.assertEqual(MODULE.EXPECTED_REQUEST, MODULE.validate_request(request))

    def test_checked_in_policy_retains_unconfigured_placeholder_for_hardening(self) -> None:
        policy_path = SOURCE_ROOT / "release-control-policy.json"
        document = json.loads(policy_path.read_text(encoding="utf-8"))
        self.assertFalse(document["bootstrapComplete"])
        self.assertEqual(
            {
                "clinical-safety": [],
                "operations": [],
                "security": [],
            },
            document["roleApprovers"],
        )
        self.assertEqual(
            {
                "signingConfigured": False,
                "expectedCertificateIdentity": MODULE.IDENTITY_PLACEHOLDER,
                "certificateOidcIssuer": MODULE.EXPECTED_ISSUER,
            },
            MODULE.validate_authenticity_policy(document["authenticity"]),
        )

    def test_malformed_noncanonical_extra_and_wrong_values_fail(self) -> None:
        variants = (
            b"not-json\n",
            json.dumps(MODULE.EXPECTED_REQUEST).encode("utf-8"),
            MODULE.canonical_bytes({**MODULE.EXPECTED_REQUEST, "extra": True}),
            MODULE.canonical_bytes(
                {**MODULE.EXPECTED_REQUEST, "combinedIdentitySha256": "0" * 64}
            ),
            MODULE.canonical_bytes(
                {**MODULE.EXPECTED_REQUEST, "schemaVersion": True}
            ),
        )
        for raw in variants:
            with self.subTest(raw=raw[:20]), tempfile.TemporaryDirectory() as directory:
                path = self.write_request(Path(directory), raw)
                with self.assertRaises(MODULE.VerificationError):
                    MODULE.validate_request(path)

    def test_request_symlink_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = self.write_request(root)
            link = root / "link.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(MODULE.VerificationError, "non-symlink"):
                MODULE.validate_request(link)

    def test_unconfigured_policy_is_explicitly_fail_closed(self) -> None:
        policy = {
            "signingConfigured": False,
            "expectedCertificateIdentity": MODULE.IDENTITY_PLACEHOLDER,
            "certificateOidcIssuer": MODULE.EXPECTED_ISSUER,
        }
        self.assertEqual(policy, MODULE.validate_authenticity_policy(policy))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = self.write_request(root)
            bundle = root / "bundle.json"
            bundle.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(MODULE.VerificationError, "not configured"):
                MODULE.verify_bundle(request, bundle, policy)

    def test_identity_must_be_exact_main_workflow_url(self) -> None:
        invalid = (
            "https://github.com/foreign-owner/link-cdss-release-control/.github/workflows/sign-authenticity-request.yml@refs/heads/main",
            "https://github.com/example/*/.github/workflows/sign-authenticity-request.yml@refs/heads/main",
            "https://github.com/example/release-control/.github/workflows/sign-authenticity-request.yml@refs/heads/*",
            "https://github.com/example/release-control/.github/workflows/other.yml@refs/heads/main",
            "^https://github.com/example/release-control/.*$",
        )
        for identity in invalid:
            with self.subTest(identity=identity):
                policy = dict(self.configured_policy)
                policy["expectedCertificateIdentity"] = identity
                with self.assertRaises(MODULE.VerificationError):
                    MODULE.validate_authenticity_policy(policy)

    @mock.patch.object(MODULE.subprocess, "run")
    def test_bundle_verification_uses_exact_identity_and_issuer(self, run) -> None:
        request_bytes = MODULE.canonical_bytes(MODULE.EXPECTED_REQUEST)
        bundle_bytes = b'{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}'

        def inspect_private_copies(command, **kwargs):
            self.assertEqual(request_bytes, Path(command[-1]).read_bytes())
            self.assertEqual(bundle_bytes, Path(command[3]).read_bytes())
            self.assertEqual(0o600, Path(command[-1]).stat().st_mode & 0o777)
            self.assertEqual(0o600, Path(command[3]).stat().st_mode & 0o777)
            return mock.Mock(returncode=0)

        run.side_effect = inspect_private_copies
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = self.write_request(root)
            bundle = root / "bundle.json"
            bundle.write_bytes(bundle_bytes)
            MODULE.verify_bundle(request, bundle, self.configured_policy, "cosign-v3.0.6")
        command = run.call_args.args[0]
        self.assertEqual("cosign-v3.0.6", command[0])
        self.assertIn(self.configured_policy["expectedCertificateIdentity"], command)
        self.assertIn(MODULE.EXPECTED_ISSUER, command)
        self.assertNotIn("--certificate-identity-regexp", command)
        self.assertNotEqual(str(request), command[-1])
        self.assertNotEqual(str(bundle), command[3])

    @mock.patch.object(MODULE.subprocess, "run")
    def test_source_replacement_cannot_change_cosign_input(self, run) -> None:
        original_request = MODULE.canonical_bytes(MODULE.EXPECTED_REQUEST)
        original_bundle = b'{"mediaType":"original"}'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = self.write_request(root, original_request)
            bundle = root / "bundle.json"
            bundle.write_bytes(original_bundle)

            def replace_sources_and_inspect(command, **kwargs):
                request.write_bytes(b'{"replaced":true}')
                bundle.write_bytes(b'{"mediaType":"replacement"}')
                self.assertEqual(original_request, Path(command[-1]).read_bytes())
                self.assertEqual(original_bundle, Path(command[3]).read_bytes())
                return mock.Mock(returncode=0)

            run.side_effect = replace_sources_and_inspect
            MODULE.verify_bundle(request, bundle, self.configured_policy)

    def test_request_and_bundle_size_limits_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = self.write_request(root, b"x" * (MODULE.MAX_REQUEST_BYTES + 1))
            with self.assertRaisesRegex(MODULE.VerificationError, "size limit"):
                MODULE.validate_request(request)
            request = self.write_request(root)
            bundle = root / "bundle.json"
            bundle.write_bytes(b"x" * (MODULE.MAX_BUNDLE_BYTES + 1))
            with self.assertRaisesRegex(MODULE.VerificationError, "size limit"):
                MODULE.verify_bundle(request, bundle, self.configured_policy)

    @mock.patch.object(MODULE.subprocess, "run")
    def test_invalid_bundle_or_cosign_rejection_fails(self, run) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = self.write_request(root)
            bundle = root / "bundle.json"
            bundle.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(MODULE.VerificationError, "object"):
                MODULE.verify_bundle(request, bundle, self.configured_policy)
            bundle.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(MODULE.VerificationError, "empty"):
                MODULE.verify_bundle(request, bundle, self.configured_policy)
            bundle.write_text('{"mediaType":"test"}', encoding="utf-8")
            run.return_value.returncode = 1
            with self.assertRaisesRegex(MODULE.VerificationError, "rejected"):
                MODULE.verify_bundle(request, bundle, self.configured_policy)


if __name__ == "__main__":
    unittest.main()
