# Link CDSS release control

This public, metadata-only repository provides GitHub Free-compatible release
approval and deployment gates for a private application repository. It is a
control plane, not an application mirror and not an evidence store.

## Public data boundary

Allowed public data is limited to release IDs, full source commit hashes,
artifact SHA-256 digests, evidence SHA-256 values, environment names, bounded
timestamps, approval issue numbers, reviewer GitHub identities, and generic
pass/fail outcomes. These values disclose release timing and allow correlation
with anyone who already possesses private build information; project governance
must explicitly accept that residual disclosure.

Never publish source, image repository names, hostnames, IP addresses,
credentials, environment files, logs, evidence contents, PHI, clinical data, or
patient, clinician, facility, tenant, or user identifiers.

## Release-set authenticity

The `authenticity/` directory publishes one canonical request binding release ID
`diagnostic-order-billing-final-lock-g-a` to its release-set manifest and
combined identity digests. A matching `authenticity-request.sigstore.json`
Cosign bundle may be committed only after the exact public GitHub repository
workflow identity is configured and a genuine keyless signature is produced by
`Sign release set authenticity request` using GitHub Actions OIDC.

The current hardening PR deliberately leaves authenticity signing unconfigured:
`authenticity.signingConfigured` is `false` and the certificate identity is the
literal fail-closed placeholder. After this hardening is trusted on protected
`main`, the next protected PR must atomically set `signingConfigured` to `true`
and bind the exact
`https://github.com/opian-tech/link-cdss-release-control/.github/workflows/sign-authenticity-request.yml@refs/heads/main`
identity. The verifier already rejects every other configured identity.
Bootstrap remains incomplete until that PR, the genuine bundle, and role
approvers are in place. See `authenticity/README.md` and `docs/bootstrap.md`; do
not substitute a wildcard, regular expression, foreign-repository identity, or
fabricated bundle.

Every release manifest must repeat the request's exact
`releaseSetManifestSha256` and `combinedIdentitySha256` values. The manifest
parser rejects any other lowercase digest or any mixed pair copied from a
different request. Deployment compares the selected manifest and generated
approval report to the canonical request before using approvals, then passes
both bindings to the protected host agent.

## Release protocol

1. The private build pipeline produces signed, attested, immutable artifacts and
   stores detailed evidence outside this repository.
2. An authorized maintainer opens an approval issue to reserve its number.
3. The maintainer creates the final manifest under `releases/` with that issue
   number, generates the exact request with
   `scripts/verify_release.py --manifest <path> --print-request`, and replaces
   the issue body before any approval is added.
4. Three distinct authorized people add unedited approval comments, one each
   for `clinical-safety`, `security`, and `operations`, then an authorized
   closer closes the issue as completed. Reviewers inspect the private,
   checksummed source-review, clinical-safety, and promotion evidence out of
   band; raw evidence is never copied here.
5. The manifest is updated with the issue number and merged through protected
   `main` after required checks and two pull-request approvals.
6. A person manually dispatches `Approved release deployment` from `main`.
7. The secretless gate validates the committed manifest and issue. GitHub then
   withholds environment secrets until a configured non-self environment
   reviewer approves the static `staging` or `prod` job.
8. The job sends validated hashes to a fixed root-owned host deployment agent.
   Detailed deployment output and evidence remain on the target environment.

Approval comments use this exact form:

```text
PUBLIC-RELEASE-APPROVED: 1
Environment: staging
Manifest-SHA256: <64 lowercase hexadecimal characters>
Role: security
Decision: approve
Evidence: reviewed private immutable release evidence
```

## Required GitHub Free configuration

Follow `docs/bootstrap.md`. The checked-in policy has `bootstrapComplete` set to
`false` and empty role lists, so all releases fail closed until accountable
clinical-safety, security, and operations approvers are assigned.

The exact scaffold, including the reviewed trusted-code digests and policy
verifier, must be established directly as trusted `main` before pull requests
are accepted. Pull-request validation executes only verifier and test bytes from
the trusted base commit; the PR head is checked out separately as inert
candidate data and cannot bootstrap or replace those controls.
Main-push validation likewise runs the previous `main` commit's verifier against
the pushed commit, preventing one pushed commit from replacing both a workflow
and the verifier that judges it.

## Trusted-code bundle rotation

`docs/trusted-code-digests.json` binds ten exact active files: all three
workflows, all six Python verifier/helper/test files, and the committed
published-base Python fixture used to prove bootstrap compatibility. Rotate
them only as one complete bundle through three separate pull requests:

The published bootstrap check labels these transitions **PR1:** Stage,
**PR2:** Promote, and **PR3:** Cleanup. These labels are compatibility aliases;
each transition still applies to the complete trusted-code bundle described
below.

1. **Stage:** leave every active trusted file and active digest unchanged. Add a
   complete `staged` mapping and matching non-executable future bytes under
   `trust/next/<active-path>`. The candidate tree is reviewable data only; no
   workflow imports or executes it. Merge through protected `main`.
2. **Promote:** replace every active trusted file and the complete `active`
   mapping with the exact staged bundle already present in the base commit.
   Retain the staged mapping and `trust/next` tree byte-for-byte. Partial,
   mixed, or simultaneous stage-and-promote changes fail closed. Merge through
   protected `main`.
3. **Cleanup:** leave active bytes and digests unchanged, then remove only the
   staged mapping and `trust/next` tree. Cleanup is accepted only when the base
   active and staged mappings are already identical. Merge through protected
   `main`.

Run tests, repository policy, and `actionlint` for every PR. The trust tree may
contain no symlinks, executable files, unknown paths, or extra files. Required
branch protection must prohibit direct pushes and every administrator or
automation bypass; the `validate-pull-request` required check must pass from
trusted base verifier bytes before each merge. A direct-main change to trusted
code or its digest manifest is not an authorized rotation path.

Run all local checks with:

```bash
python3 scripts/verify_release.py --help
python3 scripts/test_verify_release.py
python3 scripts/test_verify_authenticity.py
python3 scripts/test_verify_repository_policy.py
python3 scripts/verify_repository_policy.py --self-check .
```

Transition validation always compares distinct immutable trees. From a trusted
base checkout, the workflow-compatible positional form is
`python3 scripts/verify_repository_policy.py /path/to/candidate`; automation may
instead pass both `--trusted-root /path/to/base` and
`--candidate-root /path/to/candidate`. Supplying the same resolved root is an
error and `--self-check` never authorizes a transition.

The v3 published snapshot fixture is self-contained. It binds the raw bootstrap
commit object, its root tree, all 19 published file modes and Git/SHA-256 blob
identities, and a deterministic compressed archive containing the exact 19
files. Validation and materialization use only Python's standard library and
the committed fixture; they do not require Git, an external repository,
network access, or a machine-local bootstrap copy.

`bootstrapRecovery` is a lineage-scoped authorization, not a globally one-time
state. While present in the initial hardened lineage, including after staging,
it permits recovery only to the exact known fail-closed published snapshot.
The first promotion consumes it, and cleanup or later transitions in that
hardened lineage cannot restore it. Exact recovery deliberately leaves the
hardened lineage and returns to the manifest-less published trust state.
Reapplying hardening after recovery is a new bootstrap, requires the complete
protected two-approval process, and establishes a new lineage with a new
`bootstrapRecovery` authorization. No repository-only control can persist a
global consumption marker across that intentional return to the old state.
