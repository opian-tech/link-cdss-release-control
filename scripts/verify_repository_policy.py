#!/usr/bin/env python3
"""Fail closed when a public release-control export violates repository policy."""

from __future__ import annotations

import argparse
import base64
import binascii
import gzip
import hashlib
import io
import json
import re
import stat
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_release  # noqa: E402
import verify_authenticity  # noqa: E402


ALLOWED_ROOT_FILES = {
    ".gitignore",
    "README.md",
    "SECURITY.md",
    "release-control-policy.json",
}
ALLOWED_DIRECTORIES = {
    ".github",
    "authenticity",
    "docs",
    "releases",
    "schemas",
    "scripts",
    "trust",
}
ALLOWED_SUFFIXES = {".json", ".md", ".py", ".yml", ".yaml"}
MAX_FILES = 128
MAX_FILE_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024
MAX_COMMIT_BYTES = 64 * 1024
MAX_PUBLISHED_ARCHIVE_COMPRESSED_BYTES = 192 * 1024
MAX_PUBLISHED_ARCHIVE_BYTES = 512 * 1024
PUBLISHED_FIXTURE = "docs/published-python-controls.json"
PUBLISHED_SOURCE_COMMIT = "6f499c4770770804ace579a1bafec8838949a613"
PUBLISHED_ROOT_TREE = "a61a13379f8e4b04612160829526d73c7ed5e1ce"
APPROVED_PUBLISHED_COMMIT_IDENTITY = (
    "Link Release Control <release-control@link.invalid>"
)
PUBLISHED_SNAPSHOT_PATHS = frozenset(
    {
        ".github/workflows/deploy-approved-release.yml",
        ".github/workflows/sign-authenticity-request.yml",
        ".github/workflows/validate-control.yml",
        ".gitignore",
        "README.md",
        "SECURITY.md",
        "authenticity/README.md",
        "authenticity/authenticity-request.json",
        "docs/bootstrap.md",
        "release-control-policy.json",
        "releases/README.md",
        "schemas/authenticity-request.schema.json",
        "schemas/release-manifest.schema.json",
        "scripts/test_verify_authenticity.py",
        "scripts/test_verify_release.py",
        "scripts/test_verify_repository_policy.py",
        "scripts/verify_authenticity.py",
        "scripts/verify_release.py",
        "scripts/verify_repository_policy.py",
    }
)
PUBLISHED_PYTHON_PATHS = frozenset(
    path for path in PUBLISHED_SNAPSHOT_PATHS if path.startswith("scripts/")
)
EXPECTED_WORKFLOWS = {
    "deploy-approved-release.yml",
    "sign-authenticity-request.yml",
    "validate-control.yml",
}
TRUSTED_CODE_PATHS = frozenset(
    {
        ".github/workflows/deploy-approved-release.yml",
        ".github/workflows/sign-authenticity-request.yml",
        ".github/workflows/validate-control.yml",
        "docs/published-python-controls.json",
        "scripts/test_verify_authenticity.py",
        "scripts/test_verify_release.py",
        "scripts/test_verify_repository_policy.py",
        "scripts/verify_authenticity.py",
        "scripts/verify_release.py",
        "scripts/verify_repository_policy.py",
    }
)
TRUST_MANIFEST = "docs/trusted-code-digests.json"
STAGED_ROOT = Path("trust/next")
ALLOWED_ENVIRONMENT_SECRETS = {
    "DEPLOY_HOST",
    "DEPLOY_USER",
    "DEPLOY_SSH_PRIVATE_KEY",
    "DEPLOY_KNOWN_HOSTS",
}
ACTION_REFS = {
    "actions/checkout": "34e114876b0b11c390a56381ad16ebd13914f8d5",
    "actions/upload-artifact": "ea165f8d65b6e75b540449e92b4886f43607fa02",
    "sigstore/cosign-installer": "faadad0cce49287aee09b3a48701e75088a2c6ad",
}
WORKFLOW_ACTIONS = {
    "deploy-approved-release.yml": (
        "actions/checkout",
        "sigstore/cosign-installer",
    ),
    "sign-authenticity-request.yml": (
        "actions/checkout",
        "sigstore/cosign-installer",
        "actions/upload-artifact",
    ),
    "validate-control.yml": (
        "actions/checkout",
        "actions/checkout",
        "sigstore/cosign-installer",
        "actions/checkout",
        "actions/checkout",
        "sigstore/cosign-installer",
    ),
}
WORKFLOW_PERMISSIONS = {
    "deploy-approved-release.yml": {
        "workflow": {"contents": "read", "issues": "read"},
        "jobs": {"deploy-staging": {}, "deploy-prod": {}},
    },
    "sign-authenticity-request.yml": {
        "workflow": {"contents": "read", "id-token": "write"},
        "jobs": {},
    },
    "validate-control.yml": {
        "workflow": {"contents": "read"},
        "jobs": {},
    },
}


class PolicyError(Exception):
    pass


def repository_files(root: Path) -> list[Path]:
    if root.is_symlink() or not root.is_dir():
        raise PolicyError("repository root must be a non-symlink directory")
    files: list[Path] = []
    total = 0
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if ".git" in relative.parts:
            continue
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise PolicyError(f"symlink is prohibited: {relative}")
        if path.is_dir():
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise PolicyError(f"non-regular file is prohibited: {relative}")
        if len(relative.parts) == 1:
            if relative.name not in ALLOWED_ROOT_FILES:
                raise PolicyError(f"root file is not allowlisted: {relative}")
        else:
            if relative.parts[0] not in ALLOWED_DIRECTORIES:
                raise PolicyError(f"directory is not allowlisted: {relative}")
            if path.suffix not in ALLOWED_SUFFIXES:
                raise PolicyError(f"file type is not allowlisted: {relative}")
        if metadata.st_size > MAX_FILE_BYTES:
            raise PolicyError(f"file exceeds size limit: {relative}")
        total += metadata.st_size
        files.append(path)
    if len(files) > MAX_FILES or total > MAX_TOTAL_BYTES:
        raise PolicyError("repository export exceeds bounded size")
    return files


def scan_sensitive_content(root: Path, files: list[Path]) -> None:
    private_key = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
    token_prefix = re.compile(r"\b(?:gh" + r"[pousr]|github_pat)_[A-Za-z0-9_]{12,}")
    aws_key = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
    private_ipv4 = re.compile(
        r"(?<![0-9.])(?:10\.(?:\d{1,3}\.){2}\d{1,3}|"
        r"192\.168\.(?:\d{1,3}\.)\d{1,3}|"
        r"172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3}\.)\d{1,3})(?![0-9.])"
    )
    high_risk_names = re.compile(
        r"(?:^|/)(?:\.env(?:\..*)?|id_(?:rsa|ed25519)|credentials?|secrets?|"
        r"patient-export|clinical-export)(?:$|[./])",
        re.IGNORECASE,
    )
    for path in files:
        relative = path.relative_to(root).as_posix()
        if high_risk_names.search(relative):
            raise PolicyError(f"sensitive filename is prohibited: {relative}")
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeError as error:
            raise PolicyError(f"non-UTF-8 content is prohibited: {relative}") from error
        for label, pattern in (
            ("private key", private_key),
            ("access token", token_prefix),
            ("cloud access key", aws_key),
            ("private network address", private_ipv4),
        ):
            if pattern.search(content):
                raise PolicyError(f"possible {label} found in {relative}")


def scan_sensitive_bytes(relative: str, content: bytes) -> None:
    try:
        text = content.decode("utf-8")
    except UnicodeError as error:
        raise PolicyError(f"published archive member is not UTF-8: {relative}") from error
    patterns = (
        ("private key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
        ("access token", re.compile(r"\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{12,}")),
        ("cloud access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        (
            "credential assignment",
            re.compile(
                r"(?im)\b(?:password|client_secret|api_?key|access_?token)"
                r"\s*[:=]\s*[\"'][^\"'\r\n]{8,128}[\"']"
            ),
        ),
        (
            "private network address",
            re.compile(
                r"(?<![0-9.])(?:10\.(?:\d{1,3}\.){2}\d{1,3}|"
                r"192\.168\.(?:\d{1,3}\.)\d{1,3}|"
                r"172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3}\.)\d{1,3})(?![0-9.])"
            ),
        ),
        (
            "synthetic PHI marker",
            re.compile(
                r"(?im)\b(?:mrn|patient_?id|patientId)\s*[:=]\s*[\"']"
                r"[A-Za-z0-9][A-Za-z0-9-]{2,63}[\"']"
            ),
        ),
        (
            "personal GitHub noreply identity",
            re.compile(
                r"\b(?:\d+\+)?[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?"
                r"@users\.noreply\.github\.com\b",
                re.IGNORECASE,
            ),
        ),
    )
    for label, pattern in patterns:
        if pattern.search(text):
            raise PolicyError(f"possible {label} found in published archive member: {relative}")


def validate_published_commit_headers(commit_bytes: bytes) -> str:
    scan_sensitive_bytes("source commit", commit_bytes)
    try:
        commit_text = commit_bytes.decode("utf-8")
    except UnicodeError as error:
        raise PolicyError("published source commit is not UTF-8") from error
    headers, separator, _ = commit_text.partition("\n\n")
    if not separator:
        raise PolicyError("published source commit has no message separator")
    header_lines = headers.splitlines()
    for kind in ("author", "committer"):
        matching = [line for line in header_lines if line.startswith(f"{kind} ")]
        if len(matching) != 1:
            raise PolicyError(f"published source commit must have exactly one {kind} header")
        expected = re.compile(
            rf"{kind} {re.escape(APPROVED_PUBLISHED_COMMIT_IDENTITY)} "
            r"\d+ [+-]\d{4}"
        )
        if expected.fullmatch(matching[0]) is None:
            raise PolicyError(
                f"published source commit {kind} must use the approved neutral project identity"
            )
    return commit_text


def strip_yaml_comment(line: str) -> str:
    quote: str | None = None
    escaped = False
    for index, character in enumerate(line):
        if escaped:
            escaped = False
            continue
        if character == "\\" and quote == '"':
            escaped = True
        elif character in ("'", '"'):
            quote = None if quote == character else character if quote is None else quote
        elif character == "#" and quote is None and (
            index == 0 or line[index - 1].isspace()
        ):
            return line[:index]
    return line


def workflow_lines(workflow: str) -> list[tuple[int, int, str]]:
    parsed: list[tuple[int, int, str]] = []
    block_indent: int | None = None
    for number, raw in enumerate(workflow.splitlines(), start=1):
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise PolicyError(f"workflow indentation cannot contain tabs at line {number}")
        content = strip_yaml_comment(raw).rstrip()
        if not content.strip():
            continue
        indent = len(content) - len(content.lstrip(" "))
        if block_indent is not None:
            if indent > block_indent:
                continue
            block_indent = None
        stripped = content[indent:]
        parsed.append((number, indent, stripped))
        if re.search(r":\s*[|>]\s*(?:[-+]?[1-9])?\s*$", stripped):
            block_indent = indent
    return parsed


def active_shell_blocks(workflow: str) -> list[list[str]]:
    raw_lines = workflow.splitlines()
    blocks: list[list[str]] = []
    index = 0
    run_key = re.compile(r"(?:run|'run'|\"run\")\s*:\s*[|>]\s*(?:[-+]?[1-9])?\s*$")
    while index < len(raw_lines):
        active = strip_yaml_comment(raw_lines[index]).rstrip()
        indent = len(active) - len(active.lstrip(" "))
        if not run_key.fullmatch(active[indent:]):
            index += 1
            continue
        block: list[str] = []
        index += 1
        while index < len(raw_lines):
            active = strip_yaml_comment(raw_lines[index]).rstrip()
            child_indent = len(active) - len(active.lstrip(" "))
            if active.strip() and child_indent <= indent:
                break
            if active.strip():
                block.append(active.strip())
            index += 1
        blocks.append(block)
    return blocks


def contains_sequence(block: list[str], expected: tuple[str, ...]) -> bool:
    return any(
        tuple(block[index : index + len(expected)]) == expected
        for index in range(len(block) - len(expected) + 1)
    )


def canonical_json_bytes(document: dict[str, object]) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def git_object_id(kind: str, content: bytes) -> str:
    return hashlib.sha1(
        kind.encode("ascii") + b" " + str(len(content)).encode("ascii") + b"\0" + content
    ).hexdigest()


def validate_snapshot_path(value: object) -> str:
    if (
        not isinstance(value, str)
        or value.startswith("/")
        or "\\" in value
        or any(part in ("", ".", "..") for part in value.split("/"))
    ):
        raise PolicyError("published snapshot contains an unsafe path")
    return value


def decode_fixture_base64(value: object, label: str, maximum: int) -> bytes:
    if not isinstance(value, str) or len(value) > ((maximum + 2) // 3) * 4:
        raise PolicyError(f"{label} exceeds its encoded size bound")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise PolicyError(f"{label} must be strict base64") from error
    if len(decoded) > maximum or base64.b64encode(decoded).decode("ascii") != value:
        raise PolicyError(f"{label} must use canonical bounded base64")
    return decoded


def reconstruct_tree_id(files: dict[str, dict[str, str]]) -> str:
    nodes: dict[str, object] = {}
    for relative, record in files.items():
        current = nodes
        parts = relative.split("/")
        for part in parts[:-1]:
            child = current.setdefault(part, {})
            if not isinstance(child, dict):
                raise PolicyError("published snapshot has a file/directory collision")
            current = child
        if parts[-1] in current:
            raise PolicyError("published snapshot contains a duplicate path")
        current[parts[-1]] = record["gitBlobSha1"]

    def hash_tree(tree: dict[str, object]) -> str:
        entries: list[tuple[bytes, bytes]] = []
        for name, value in tree.items():
            encoded_name = name.encode("utf-8")
            if isinstance(value, dict):
                mode = b"40000"
                object_id = hash_tree(value)
            else:
                mode = b"100644"
                object_id = value
            entries.append((encoded_name, mode + b" " + encoded_name + b"\0" + bytes.fromhex(object_id)))
        entries.sort(key=lambda entry: entry[0] + (b"/" if isinstance(tree[entry[0].decode("utf-8")], dict) else b""))
        return git_object_id("tree", b"".join(entry for _, entry in entries))

    return hash_tree(nodes)


def canonical_published_archive(contents: dict[str, bytes]) -> tuple[bytes, bytes]:
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for relative in sorted(contents):
            content = contents[relative]
            member = tarfile.TarInfo(relative)
            member.size = len(content)
            member.mode = 0o644
            member.mtime = 0
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            archive.addfile(member, io.BytesIO(content))
    tar_bytes = tar_buffer.getvalue()
    gzip_buffer = io.BytesIO()
    with gzip.GzipFile(
        filename="", mode="wb", compresslevel=9, fileobj=gzip_buffer, mtime=0
    ) as compressed:
        compressed.write(tar_bytes)
    return gzip_buffer.getvalue(), tar_bytes


def load_published_archive(document: dict[str, object]) -> dict[str, bytes]:
    archive_record = document.get("archive")
    if not isinstance(archive_record, dict) or set(archive_record) != {
        "base64",
        "compressedSha256",
        "compressedSize",
        "format",
        "tarSize",
    }:
        raise PolicyError("published archive must use the exact schema")
    if archive_record.get("format") != "canonical-tar-gzip-v1":
        raise PolicyError("published archive format is unsupported")
    compressed = decode_fixture_base64(
        archive_record.get("base64"),
        "published compressed archive",
        MAX_PUBLISHED_ARCHIVE_COMPRESSED_BYTES,
    )
    if type(archive_record.get("compressedSize")) is not int or archive_record[
        "compressedSize"
    ] != len(compressed):
        raise PolicyError("published compressed archive size mismatch")
    if not isinstance(archive_record.get("compressedSha256"), str) or hashlib.sha256(
        compressed
    ).hexdigest() != archive_record["compressedSha256"]:
        raise PolicyError("published compressed archive SHA-256 mismatch")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(compressed), mode="rb") as gzip_file:
            tar_bytes = gzip_file.read(MAX_PUBLISHED_ARCHIVE_BYTES + 1)
    except (EOFError, OSError) as error:
        raise PolicyError("published compressed archive is malformed") from error
    if len(tar_bytes) > MAX_PUBLISHED_ARCHIVE_BYTES:
        raise PolicyError("published archive exceeds its decompressed size bound")
    if type(archive_record.get("tarSize")) is not int or archive_record["tarSize"] != len(
        tar_bytes
    ):
        raise PolicyError("published archive decompressed size mismatch")

    contents: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as archive:
            members = archive.getmembers()
            for member in members:
                relative = validate_snapshot_path(member.name)
                if not member.isreg():
                    raise PolicyError(
                        f"published archive member must be a regular file: {relative}"
                    )
                if member.mode != 0o644:
                    raise PolicyError(f"published archive member mode mismatch: {relative}")
                if member.size > MAX_FILE_BYTES:
                    raise PolicyError(f"published archive member exceeds size bound: {relative}")
                if relative in contents:
                    raise PolicyError(f"published archive contains a duplicate path: {relative}")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise PolicyError(f"published archive member cannot be read: {relative}")
                content = extracted.read(MAX_FILE_BYTES + 1)
                if len(content) != member.size:
                    raise PolicyError(f"published archive member size mismatch: {relative}")
                contents[relative] = content
    except (tarfile.TarError, UnicodeError) as error:
        raise PolicyError("published tar archive is malformed") from error
    if set(contents) != PUBLISHED_SNAPSHOT_PATHS:
        raise PolicyError("published archive must contain exactly all 19 snapshot files")
    canonical_compressed, canonical_tar = canonical_published_archive(contents)
    if tar_bytes != canonical_tar or compressed != canonical_compressed:
        raise PolicyError("published archive must use deterministic canonical bytes")
    return contents


def load_published_fixture(root: Path) -> dict[str, object]:
    path = root / PUBLISHED_FIXTURE
    try:
        raw = path.read_bytes()
        document = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PolicyError("published snapshot fixture must be valid UTF-8 JSON") from error
    if not isinstance(document, dict) or set(document) != {
        "archive",
        "formatVersion",
        "sourceCommit",
        "files",
    }:
        raise PolicyError("published snapshot fixture must use the exact v3 schema")
    if document.get("formatVersion") != 3:
        raise PolicyError("published snapshot fixture formatVersion must be 3")

    source = document.get("sourceCommit")
    if not isinstance(source, dict) or set(source) != {"objectId", "rawBase64", "rootTree"}:
        raise PolicyError("published source commit must use the exact schema")
    commit_bytes = decode_fixture_base64(source.get("rawBase64"), "published commit", MAX_COMMIT_BYTES)
    commit_text = validate_published_commit_headers(commit_bytes)
    if source.get("objectId") != PUBLISHED_SOURCE_COMMIT:
        raise PolicyError("published source commit ID is unexpected")
    if git_object_id("commit", commit_bytes) != source["objectId"]:
        raise PolicyError("published source commit bytes do not reconstruct its ID")
    tree_lines = [line for line in commit_text.splitlines() if line.startswith("tree ")]
    if tree_lines != [f"tree {source.get('rootTree')}"]:
        raise PolicyError("published source commit has an invalid root tree binding")
    if source.get("rootTree") != PUBLISHED_ROOT_TREE:
        raise PolicyError("published root tree ID is unexpected")

    file_value = document.get("files")
    if not isinstance(file_value, dict) or set(file_value) != PUBLISHED_SNAPSHOT_PATHS:
        raise PolicyError("published snapshot must contain exactly all 19 published paths")
    files: dict[str, dict[str, str]] = {}
    for raw_relative, raw_record in file_value.items():
        relative = validate_snapshot_path(raw_relative)
        if not isinstance(raw_record, dict) or set(raw_record) != {
            "gitBlobSha1",
            "mode",
            "sha256",
        }:
            raise PolicyError(f"published snapshot record has unknown fields: {relative}")
        if raw_record.get("mode") != "100644":
            raise PolicyError(f"published snapshot mode must be 100644: {relative}")
        if not isinstance(raw_record.get("gitBlobSha1"), str) or re.fullmatch(
            r"[0-9a-f]{40}", raw_record["gitBlobSha1"]
        ) is None:
            raise PolicyError(f"published snapshot blob ID is malformed: {relative}")
        if not isinstance(raw_record.get("sha256"), str) or re.fullmatch(
            r"[0-9a-f]{64}", raw_record["sha256"]
        ) is None:
            raise PolicyError(f"published snapshot SHA-256 is malformed: {relative}")
        files[relative] = raw_record
    contents = load_published_archive(document)
    for relative, content in contents.items():
        scan_sensitive_bytes(relative, content)
        snapshot = files[relative]
        if git_object_id("blob", content) != snapshot["gitBlobSha1"]:
            raise PolicyError(f"published archive blob ID mismatch: {relative}")
        if hashlib.sha256(content).hexdigest() != snapshot["sha256"]:
            raise PolicyError(f"published archive SHA-256 mismatch: {relative}")
    if reconstruct_tree_id(files) != source["rootTree"]:
        raise PolicyError("published snapshot does not reconstruct the bound root tree")
    if raw != canonical_json_bytes(document):
        raise PolicyError("published snapshot fixture must use canonical JSON encoding")
    return document


def materialize_published_snapshot(fixture_root: Path, destination: Path) -> None:
    document = load_published_fixture(fixture_root)
    contents = load_published_archive(document)
    if destination.exists() or destination.is_symlink():
        raise PolicyError("published snapshot destination must not already exist")
    destination.mkdir(parents=True, mode=0o755)
    for relative, content in contents.items():
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        target.chmod(0o644)


def validate_digest_mapping(value: object, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != TRUSTED_CODE_PATHS:
        raise PolicyError(f"{label} trusted-code mapping must cover exactly all trusted paths")
    mapping: dict[str, str] = {}
    for path, digest in value.items():
        if (
            not isinstance(path, str)
            or path.startswith("/")
            or "\\" in path
            or any(part in ("", ".", "..") for part in path.split("/"))
        ):
            raise PolicyError(f"{label} trusted-code mapping contains an unsafe path")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise PolicyError(f"{label} trusted-code mapping contains a malformed digest: {path}")
        mapping[path] = digest
    return mapping


def load_trust_manifest(root: Path) -> dict[str, object]:
    path = root / TRUST_MANIFEST
    try:
        raw = path.read_bytes()
        document = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PolicyError("trusted-code digest manifest must be valid UTF-8 JSON") from error
    if not isinstance(document, dict) or not set(document) <= {
        "version",
        "active",
        "staged",
        "bootstrapRecovery",
    }:
        raise PolicyError("trusted-code digest manifest contains unknown fields")
    required = {"version", "active"}
    if not required <= set(document):
        raise PolicyError("trusted-code digest manifest is incomplete")
    if document.get("version") != 2:
        raise PolicyError("trusted-code digest manifest version must be 2")
    document["active"] = validate_digest_mapping(document.get("active"), "active")
    if "staged" in document:
        document["staged"] = validate_digest_mapping(document["staged"], "staged")
    if "bootstrapRecovery" in document and document["bootstrapRecovery"] != {
        "sourceCommit": PUBLISHED_SOURCE_COMMIT,
        "rootTree": PUBLISHED_ROOT_TREE,
    }:
        raise PolicyError("bootstrap recovery authorization is malformed")
    if raw != canonical_json_bytes(document):
        raise PolicyError("trusted-code digest manifest must use canonical JSON encoding")
    return document


def validate_trusted_bytes(
    root: Path, mapping: dict[str, str], prefix: Path = Path()
) -> None:
    for relative, expected in mapping.items():
        path = root / prefix / relative
        try:
            metadata = path.lstat()
        except OSError as error:
            raise PolicyError(f"trusted-code file is missing: {(prefix / relative).as_posix()}") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise PolicyError(f"trusted-code file must be regular: {(prefix / relative).as_posix()}")
        if metadata.st_mode & 0o111:
            raise PolicyError(
                f"executable trusted-code file is prohibited: {(prefix / relative).as_posix()}"
            )
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise PolicyError(f"trusted-code byte digest mismatch: {(prefix / relative).as_posix()}")


def validate_staged_tree(root: Path, staged: dict[str, str] | None) -> None:
    trust = root / "trust"
    if staged is None:
        if trust.exists() or trust.is_symlink():
            raise PolicyError("trust tree is prohibited without a staged mapping")
        return
    expected = {STAGED_ROOT / path for path in TRUSTED_CODE_PATHS}
    if not trust.is_dir() or trust.is_symlink():
        raise PolicyError("complete staged trust/next tree is required")
    actual: set[Path] = set()
    for path in sorted(trust.rglob("*")):
        relative = path.relative_to(root)
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise PolicyError(f"symlink is prohibited in staged trust tree: {relative}")
        if path.is_dir():
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise PolicyError(f"non-regular staged trust file is prohibited: {relative}")
        if metadata.st_mode & 0o111:
            raise PolicyError(f"executable staged trust file is prohibited: {relative}")
        actual.add(relative)
    if actual != expected:
        raise PolicyError("staged trust tree must contain exactly the complete trusted-code bundle")
    validate_trusted_bytes(root, staged, STAGED_ROOT)


def validate_trust_state(root: Path) -> dict[str, object]:
    load_published_fixture(root)
    document = load_trust_manifest(root)
    active = document["active"]
    assert isinstance(active, dict)
    validate_trusted_bytes(root, active)
    staged = document.get("staged")
    assert staged is None or isinstance(staged, dict)
    validate_staged_tree(root, staged)
    return document


def validate_published_recovery(root: Path, fixture: dict[str, object]) -> None:
    file_records = fixture["files"]
    assert isinstance(file_records, dict)
    expected_contents = load_published_archive(fixture)
    actual: dict[str, Path] = {}
    if root.is_symlink() or not root.is_dir():
        raise PolicyError("recovery root must be a non-symlink directory")
    for path in sorted(root.rglob("*")):
        relative_path = path.relative_to(root)
        if ".git" in relative_path.parts:
            continue
        metadata = path.lstat()
        relative = relative_path.as_posix()
        if stat.S_ISLNK(metadata.st_mode):
            raise PolicyError(f"published recovery contains a symlink: {relative}")
        if path.is_dir():
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise PolicyError(f"published recovery contains a non-regular file: {relative}")
        actual[relative] = path
    if set(actual) != PUBLISHED_SNAPSHOT_PATHS:
        raise PolicyError("published recovery must contain exactly all 19 snapshot files")
    files = list(actual.values())
    scan_sensitive_content(root, files)
    for relative, path in actual.items():
        metadata = path.lstat()
        if stat.S_IMODE(metadata.st_mode) != 0o644:
            raise PolicyError(f"published recovery mode mismatch: {relative}")
        content = path.read_bytes()
        record = file_records[relative]
        assert isinstance(record, dict)
        if content != expected_contents[relative]:
            raise PolicyError(f"published recovery byte mismatch: {relative}")
        if git_object_id("blob", content) != record["gitBlobSha1"]:
            raise PolicyError(f"published recovery blob ID mismatch: {relative}")
        if hashlib.sha256(content).hexdigest() != record["sha256"]:
            raise PolicyError(f"published recovery SHA-256 mismatch: {relative}")


def validate_trusted_code_transition(trusted_root: Path, candidate_root: Path) -> str:
    base = validate_trust_state(trusted_root)
    authorization = base.get("bootstrapRecovery")
    candidate_manifest = candidate_root / TRUST_MANIFEST
    if not candidate_manifest.exists() and not candidate_manifest.is_symlink():
        if authorization is None:
            raise PolicyError("published recovery is not authorized")
        validate_published_recovery(candidate_root, load_published_fixture(trusted_root))
        return "bootstrap-recovery"
    candidate = validate_trust_state(candidate_root)
    base_active = base["active"]
    candidate_active = candidate["active"]
    base_staged = base.get("staged")
    candidate_staged = candidate.get("staged")

    candidate_authorization = candidate.get("bootstrapRecovery")
    if authorization is None and candidate_authorization is not None:
        raise PolicyError("bootstrap recovery authorization cannot be restored")
    if candidate == base:
        return "unchanged"
    if (
        base_staged is None
        and candidate_active == base_active
        and candidate_staged is not None
        and candidate_staged != base_active
        and candidate_authorization == authorization
    ):
        return "stage"
    if (
        base_staged is not None
        and base_staged != base_active
        and candidate_active == base_staged
        and candidate_staged == base_staged
        and authorization is not None
        and candidate_authorization is None
    ):
        return "promote"
    if (
        base_staged is not None
        and base_staged != base_active
        and candidate_active == base_staged
        and candidate_staged == base_staged
        and authorization is None
        and candidate_authorization is None
    ):
        return "promote"
    if (
        base_staged is not None
        and base_active == base_staged
        and candidate_active == base_active
        and candidate_staged is None
        and candidate_authorization == authorization
    ):
        return "cleanup"
    raise PolicyError(
        "trusted-code transition must be unchanged, stage, exact promotion, or cleanup"
    )


def scalar_value(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def validate_action_allowlist(path: Path, lines: list[tuple[int, int, str]]) -> None:
    actions: list[str] = []
    uses_key = re.compile(r"^(?:-\s*)?(?:uses|'uses'|\"uses\")\s*:\s*(.+)$")
    possible_uses = re.compile(r"(?:^|[{,\s])(?:uses|'uses'|\"uses\")\s*:")
    for number, _, content in lines:
        match = uses_key.fullmatch(content)
        if not match:
            if possible_uses.search(content):
                raise PolicyError(
                    f"unsupported uses syntax in {path.name} at line {number}"
                )
            continue
        reference = scalar_value(match.group(1))
        remote = re.fullmatch(
            r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?)@([0-9a-f]{40})",
            reference,
        )
        if remote is None:
            raise PolicyError(
                f"every uses entry must be a recognized remote action at a full lowercase commit SHA: {path.name}"
            )
        action, commit = remote.groups()
        if ACTION_REFS.get(action) != commit:
            raise PolicyError(f"workflow action is not allowlisted: {path.name}: {action}")
        actions.append(action)
    if tuple(actions) != WORKFLOW_ACTIONS[path.name]:
        raise PolicyError(f"workflow action allowlist is invalid: {path.name}")


def parse_permissions(
    path: Path, lines: list[tuple[int, int, str]]
) -> dict[str, object]:
    top_level: dict[str, str] | None = None
    jobs: dict[str, dict[str, str]] = {}
    current_job: str | None = None
    possible_permission = re.compile(
        r"(?:^|[{,\s])(?:permissions|'permissions'|\"permissions\")\s*:"
    )
    index = 0
    while index < len(lines):
        number, indent, content = lines[index]
        job_match = re.fullmatch(r"([A-Za-z0-9_-]+):", content)
        if indent == 2 and job_match:
            current_job = job_match.group(1)
        permission = re.fullmatch(
            r"(?:permissions|'permissions'|\"permissions\")\s*:\s*(.*)", content
        )
        if not permission:
            if possible_permission.search(content):
                raise PolicyError(
                    f"unsupported permissions syntax in {path.name} at line {number}"
                )
            index += 1
            continue
        if indent not in (0, 4) or (indent == 4 and current_job is None):
            raise PolicyError(
                f"unexpected permissions block in {path.name} at line {number}"
            )
        scalar = scalar_value(permission.group(1))
        if scalar in ("read-all", "write-all"):
            raise PolicyError(f"broad permissions are prohibited in {path.name}")
        values: dict[str, str] = {}
        if scalar:
            if scalar != "{}":
                raise PolicyError(f"permissions must be an explicit mapping in {path.name}")
        else:
            child_indent: int | None = None
            cursor = index + 1
            while cursor < len(lines) and lines[cursor][1] > indent:
                child_number, child_space, child = lines[cursor]
                if child_indent is None:
                    child_indent = child_space
                if child_space != child_indent:
                    raise PolicyError(
                        f"nested permissions are prohibited in {path.name} at line {child_number}"
                    )
                item = re.fullmatch(r"([a-z-]+):\s*(read|write|none)", child)
                if item is None or item.group(1) in values:
                    raise PolicyError(
                        f"invalid permissions entry in {path.name} at line {child_number}"
                    )
                values[item.group(1)] = item.group(2)
                cursor += 1
            index = cursor - 1
        if indent == 0:
            if top_level is not None:
                raise PolicyError(f"duplicate workflow permissions in {path.name}")
            top_level = values
        else:
            if current_job in jobs:
                raise PolicyError(f"duplicate job permissions in {path.name}")
            jobs[current_job] = values
        index += 1
    return {"workflow": top_level, "jobs": jobs}


def validate_control_validation_workflow(validation: str) -> None:
    required = (
        "pull_request_target:",
        "push:\n    branches: [main]",
        "permissions:\n  contents: read",
        "if: github.event_name == 'pull_request_target' && github.event.pull_request.base.ref == 'main'",
        "if: github.event_name == 'push' && github.ref == 'refs/heads/main'",
        "github.event.before != '0000000000000000000000000000000000000000'",
        "repository: ${{ github.event.pull_request.head.repo.full_name }}",
        "ref: ${{ github.event.pull_request.base.sha }}",
        "ref: ${{ github.event.pull_request.head.sha }}",
        "PUBLIC_REPOSITORY_UNDER_TEST: ${{ github.workspace }}/candidate",
        'run: python3 scripts/verify_repository_policy.py "$CANDIDATE_ROOT"',
    )
    for value in required:
        if value not in validation:
            raise PolicyError(f"validation workflow is missing trusted PR control: {value}")

    exact_counts = {
        "repository: ${{ github.repository }}": 3,
        "ref: ${{ github.sha }}": 1,
        "ref: ${{ github.event.before }}": 1,
        "path: trusted": 2,
        "path: candidate": 2,
        "fetch-depth: 1": 4,
        "persist-credentials: false": 4,
        "working-directory: trusted": 8,
        "cosign-release: v3.0.6": 2,
    }
    for value, expected in exact_counts.items():
        if validation.count(value) != expected:
            raise PolicyError(
                f"validation workflow trusted path/ref count is invalid: {value}"
            )

    run_commands = [
        scalar_value(match.group(1))
        for _, _, line in workflow_lines(validation)
        if (match := re.fullmatch(r"(?:run|'run'|\"run\")\s*:\s*(.+)", line))
    ]
    expected_commands = [
        "python3 scripts/test_verify_release.py",
        "python3 scripts/test_verify_authenticity.py",
        "python3 scripts/test_verify_repository_policy.py",
        'python3 scripts/verify_repository_policy.py "$CANDIDATE_ROOT"',
    ] * 2
    if run_commands != expected_commands:
        raise PolicyError(
            "validation workflow may execute only trusted verifier and test commands"
        )
    if "secrets." in validation.lower() or "pull_request:" in validation:
        raise PolicyError("validation workflow must be secretless and use trusted PR validation")
    for forbidden in (
        "working-directory: candidate",
        "pythonpath",
        "candidate/scripts",
        "source candidate",
        "bash candidate",
        "sh candidate",
        "run: ./candidate",
    ):
        if forbidden in validation.lower():
            raise PolicyError(
                f"validation workflow may not execute or import candidate code: {forbidden}"
            )


def validate_workflows(root: Path) -> None:
    workflows = root / ".github" / "workflows"
    actual = {path.name for path in workflows.glob("*.yml")}
    actual.update(path.name for path in workflows.glob("*.yaml"))
    if actual != EXPECTED_WORKFLOWS:
        raise PolicyError("workflow allowlist does not match expected files")

    for path in sorted(workflows.iterdir()):
        text = path.read_text(encoding="utf-8")
        lines = workflow_lines(text)
        lowered = text.lower()
        for forbidden in (
            "workflow_run:",
            "self-hosted",
            "ssh-keyscan",
            "continue-on-error:",
            "curl ",
            "wget ",
            "eval ",
        ):
            if forbidden in lowered:
                raise PolicyError(f"unsafe workflow construct in {path.name}: {forbidden}")
        if path.name != "validate-control.yml" and "pull_request_target:" in lowered:
            raise PolicyError(
                f"unsafe workflow construct in {path.name}: pull_request_target:"
            )
        validate_action_allowlist(path, lines)
        if parse_permissions(path, lines) != WORKFLOW_PERMISSIONS[path.name]:
            raise PolicyError(f"workflow permissions are not allowlisted: {path.name}")

    validation = (workflows / "validate-control.yml").read_text(encoding="utf-8")
    validate_control_validation_workflow(validation)

    signing = (workflows / "sign-authenticity-request.yml").read_text(encoding="utf-8")
    required_signing_controls = (
        "workflow_dispatch:",
        "permissions:\n  contents: read\n  id-token: write",
        "if: github.ref == 'refs/heads/main'",
        "ref: ${{ github.sha }}",
        "persist-credentials: false",
        "cosign-release: v3.0.6",
        "cosign sign-blob --yes --bundle",
        "cosign verify-blob",
        'test "$identity" != "REPLACE_WITH_EXACT_PUBLIC_REPOSITORY_WORKFLOW_IDENTITY"',
        '--certificate-identity "$identity"',
        '--certificate-oidc-issuer "$issuer"',
        'test "$identity" = "https://github.com/$GITHUB_REPOSITORY/.github/workflows/sign-authenticity-request.yml@refs/heads/main"',
        "${{ runner.temp }}/authenticity-request.json",
        "${{ runner.temp }}/authenticity-request.sigstore.json",
    )
    for value in required_signing_controls:
        if value not in signing:
            raise PolicyError(f"signing workflow is missing required control: {value}")
    for forbidden in (
        "contents: write",
        "packages: write",
        "repository:",
        "git push",
        "deploy",
        "secrets.",
        "--certificate-identity-regexp",
    ):
        if forbidden in signing.lower():
            raise PolicyError(f"signing workflow contains prohibited capability: {forbidden}")
    artifact_paths = re.findall(
        r"^\s{12}(\$\{\{ runner\.temp \}\}/[^\s]+)$", signing, re.MULTILINE
    )
    if artifact_paths != [
        "${{ runner.temp }}/authenticity-request.json",
        "${{ runner.temp }}/authenticity-request.sigstore.json",
    ]:
        raise PolicyError("signing workflow artifact allowlist is invalid")

    deploy = (workflows / "deploy-approved-release.yml").read_text(encoding="utf-8")
    required = (
        "workflow_dispatch:",
        "if: github.ref == 'refs/heads/main'",
        "ref: ${{ github.sha }}",
        "persist-credentials: false",
        "cosign-release: v3.0.6",
        "python3 scripts/verify_authenticity.py",
        "--bundle authenticity/authenticity-request.sigstore.json",
        "release_set_manifest_sha256: ${{ steps.release.outputs.release_set_manifest_sha256 }}",
        "combined_identity_sha256: ${{ steps.release.outputs.combined_identity_sha256 }}",
        "environment:\n      name: staging\n",
        "environment:\n      name: prod\n",
        "StrictHostKeyChecking=yes",
        "UserKnownHostsFile=\"$known_hosts\"",
        "/usr/local/libexec/link/deploy-approved-release",
    )
    for value in required:
        if value not in deploy:
            raise PolicyError(f"deployment workflow is missing required control: {value}")
    deploy_blocks = active_shell_blocks(deploy)
    tracked_authenticity = (
        "git ls-files --error-unmatch -- \\",
        "authenticity/authenticity-request.json \\",
        "authenticity/authenticity-request.sigstore.json >/dev/null",
    )
    verify_authenticity = (
        "python3 scripts/verify_authenticity.py \\",
        "--request authenticity/authenticity-request.json \\",
        "--bundle authenticity/authenticity-request.sigstore.json \\",
        "--policy release-control-policy.json \\",
        "--cosign cosign",
    )
    if not any(
        contains_sequence(block, tracked_authenticity)
        and contains_sequence(block, verify_authenticity)
        for block in deploy_blocks
    ):
        raise PolicyError(
            "deployment workflow must actively verify the tracked authenticity bundle"
        )
    manifest_bindings = (
        'release_set_manifest_sha256="$(jq -er \'.releaseSetManifestSha256\' authenticity/authenticity-request.json)"',
        'combined_identity_sha256="$(jq -er \'.combinedIdentitySha256\' authenticity/authenticity-request.json)"',
        'test "$(jq -er \'.releaseSetManifestSha256\' "$MANIFEST_PATH")" = "$release_set_manifest_sha256"',
        'test "$(jq -er \'.combinedIdentitySha256\' "$MANIFEST_PATH")" = "$combined_identity_sha256"',
    )
    report_bindings = (
        'test "$(jq -er \'.releaseSetManifestSha256\' "$report")" = "$release_set_manifest_sha256"',
        'test "$(jq -er \'.combinedIdentitySha256\' "$report")" = "$combined_identity_sha256"',
    )
    release_blocks = [
        block
        for block in deploy_blocks
        if any("python3 scripts/verify_release.py" in line for line in block)
    ]
    if len(release_blocks) != 1:
        raise PolicyError("deployment workflow must have one active release verification block")
    release_block = release_blocks[0]
    if not contains_sequence(release_block, manifest_bindings) or not contains_sequence(
        release_block, report_bindings
    ):
        raise PolicyError(
            "deployment workflow must bind manifest and report to the authenticity request"
        )
    release_command = release_block.index("python3 scripts/verify_release.py \\")
    if release_block.index(manifest_bindings[-1]) >= release_command:
        raise PolicyError("manifest authenticity binding must precede approval verification")
    for argument in (
        '--release-set-manifest-sha256 "${{ needs.gate.outputs.release_set_manifest_sha256 }}" \\',
        '--combined-identity-sha256 "${{ needs.gate.outputs.combined_identity_sha256 }}" \\',
    ):
        if sum(argument in block for block in deploy_blocks) != 2:
            raise PolicyError(
                "both deployment jobs must pass authenticity bindings to the host agent"
            )
    if re.search(r"^    environment:\s*\$\{\{", deploy, re.MULTILINE):
        raise PolicyError("deployment environments must be static")
    gate_start = deploy.find("  gate:")
    deploy_start = deploy.find("  deploy-staging:")
    if gate_start < 0 or deploy_start < 0 or gate_start >= deploy_start:
        raise PolicyError("deployment gate job boundary is invalid")
    gate = deploy[gate_start:deploy_start]
    if "secrets." in gate or re.search(r"^    environment:\s*", gate, re.MULTILINE):
        raise PolicyError("verification gate cannot receive an environment or secrets")
    secret_names = set(re.findall(r"secrets\.([A-Za-z0-9_]+)", deploy))
    if secret_names != ALLOWED_ENVIRONMENT_SECRETS:
        raise PolicyError("deployment secret allowlist does not match policy")

def load_policy_document(root: Path) -> dict[str, object]:
    try:
        document = json.loads(
            (root / "release-control-policy.json").read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PolicyError("release control policy must be valid UTF-8 JSON") from error
    if not isinstance(document, dict):
        raise PolicyError("release control policy must contain a JSON object")
    return document


def validate_authenticity_documents(
    root: Path, policy_document: dict[str, object]
) -> None:
    directory = root / "authenticity"
    allowed = {
        "README.md",
        "authenticity-request.json",
        "authenticity-request.sigstore.json",
    }
    actual = {
        path.name for path in directory.iterdir() if path.is_file() or path.is_symlink()
    }
    if not {"README.md", "authenticity-request.json"} <= actual or not actual <= allowed:
        raise PolicyError("authenticity directory allowlist is invalid")
    request = directory / "authenticity-request.json"
    bundle = directory / "authenticity-request.sigstore.json"
    try:
        verify_authenticity.validate_request(request)
        policy = verify_authenticity.validate_authenticity_policy(
            policy_document.get("authenticity")
        )
        bootstrap_complete = policy_document.get("bootstrapComplete") is True
        if bootstrap_complete and policy["signingConfigured"] is not True:
            raise verify_authenticity.VerificationError(
                "completed bootstrap requires configured authenticity signing"
            )
        if bootstrap_complete and not (bundle.exists() or bundle.is_symlink()):
            raise verify_authenticity.VerificationError(
                "completed bootstrap requires a committed Sigstore bundle"
            )
        if bundle.exists() or bundle.is_symlink():
            verify_authenticity.verify_bundle(request, bundle, policy)
    except verify_authenticity.VerificationError as error:
        raise PolicyError(f"authenticity validation failed: {error}") from error


def validate_release_documents(root: Path, policy_document: dict[str, object]) -> None:
    manifests = sorted((root / "releases").glob("*.json"))
    if policy_document.get("bootstrapComplete") is not True:
        if manifests:
            raise PolicyError("release manifests are prohibited before bootstrap completes")
        return
    try:
        policy = verify_release.validate_policy(policy_document)
        for path in manifests:
            manifest = verify_release.validate_manifest(
                verify_release.load_json(path),
                policy,
                datetime.now(timezone.utc),
                require_current=False,
            )
            verify_release.validate_manifest_path(path, root, manifest)
    except verify_release.VerificationError as error:
        raise PolicyError(f"release manifest validation failed: {error}") from error


def validate_candidate_content(root: Path) -> dict[str, int]:
    files = repository_files(root)
    scan_sensitive_content(root, files)
    validate_workflows(root)
    policy_document = load_policy_document(root)
    validate_authenticity_documents(root, policy_document)
    validate_release_documents(root, policy_document)
    return {"files": len(files), "bytes": sum(path.stat().st_size for path in files)}


def validate_self_check(root: Path) -> dict[str, int]:
    result = validate_candidate_content(root)
    validate_trust_state(root)
    return result


def validate_transition(trusted_root: Path, candidate_root: Path) -> dict[str, int]:
    if trusted_root.resolve() == candidate_root.resolve():
        raise PolicyError("transition roots must resolve to distinct directories")
    transition = validate_trusted_code_transition(trusted_root, candidate_root)
    if transition == "bootstrap-recovery":
        files = [
            path
            for path in candidate_root.rglob("*")
            if path.is_file() and ".git" not in path.relative_to(candidate_root).parts
        ]
        return {"files": len(files), "bytes": sum(path.stat().st_size for path in files)}
    return validate_candidate_content(candidate_root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", nargs="?")
    parser.add_argument("--trusted-root")
    parser.add_argument("--candidate-root")
    parser.add_argument("--self-check")
    args = parser.parse_args()
    if args.self_check is not None:
        if args.repository is not None or args.trusted_root is not None or args.candidate_root is not None:
            parser.error("--self-check cannot be combined with transition arguments")
    elif args.repository is not None:
        if args.trusted_root is not None or args.candidate_root is not None:
            parser.error("legacy positional candidate cannot be combined with root flags")
    elif (args.trusted_root is None) != (args.candidate_root is None):
        parser.error("--trusted-root and --candidate-root must be supplied together")
    elif args.trusted_root is None:
        parser.error("choose --self-check ROOT or a trusted/candidate transition")
    try:
        if args.self_check is not None:
            result = validate_self_check(Path(args.self_check).resolve())
        else:
            trusted_root = Path(args.trusted_root or ".").resolve()
            candidate_root = Path(args.candidate_root or args.repository).resolve()
            result = validate_transition(trusted_root, candidate_root)
        print(f"public release-control policy passed: {result['files']} files, {result['bytes']} bytes")
        return 0
    except (OSError, PolicyError) as error:
        print(f"public release-control policy failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
