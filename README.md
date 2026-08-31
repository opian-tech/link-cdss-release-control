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

The current `release-control-policy.json` is explicitly fail closed for
authenticity signing because the public repository slug is not yet known. See
`authenticity/README.md` and `docs/bootstrap.md`; do not substitute a wildcard,
regular expression, private-repository identity, or fabricated bundle.

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

The exact scaffold, including the reviewed workflow hashes and trusted policy
verifier, must be established directly as trusted `main` before pull requests
are accepted. Pull-request validation executes only verifier and test bytes from
the trusted base commit; the PR head is checked out separately as inert
candidate data and cannot bootstrap or replace those controls.
Main-push validation likewise runs the previous `main` commit's verifier against
the pushed commit, preventing one pushed commit from replacing both a workflow
and the verifier that judges it.

## Trusted workflow hash rotation

Each workflow has a bounded set of approved byte digests in
`scripts/verify_repository_policy.py`: one digest normally and at most two
during a transition. Rotate one workflow through three separate pull requests:

1. **PR1:** leave the workflow unchanged and add its reviewed future SHA-256 to
   the set beside the current hash. Merge through protected `main`.
2. **PR2:** change only the workflow to the exact future bytes already allowed
   by trusted `main`. Merge through protected `main`.
3. **PR3:** leave the workflow unchanged and remove the old hash, restoring a
   singleton set. Merge through protected `main`.

Run tests, repository policy, and `actionlint` for every PR. Never combine PR1
and PR2, retain more than two hashes, or leave a transition set after PR3.
Required branch protection must prohibit direct pushes and every administrator
or automation bypass; the `Validate public release control` required check must
pass from trusted base verifier bytes before each merge. A direct-main change to
the workflow and its allowlist is not an authorized rotation path.

Run all local checks with:

```bash
python3 scripts/verify_release.py --help
python3 scripts/test_verify_release.py
python3 scripts/test_verify_authenticity.py
python3 scripts/test_verify_repository_policy.py
python3 scripts/verify_repository_policy.py .
```
