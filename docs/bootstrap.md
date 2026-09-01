# GitHub Free bootstrap

## Repository

1. Create a new **public** organization repository dedicated to release control.
2. Copy only the contents of this scaffold. Do not copy application history,
   source, issues, Actions artifacts, secrets, logs, or release evidence.
3. Establish this exact scaffold directly on `main` before accepting or enabling
   pull requests. This initial trusted-base bootstrap is required because PR
   validation runs the workflow, tests, and policy verifier from the trusted
   base commit and treats the PR head only as inert candidate data. Confirm the
   checked-in `docs/trusted-code-digests.json` contract before opening the
   repository to PRs.
4. Assign the minimum required collaborators. Keep organization owner access
   narrowly held and independently reviewed.
5. Replace `REPLACE_WITH_EXACT_PUBLIC_REPOSITORY_WORKFLOW_IDENTITY` with the
   literal identity
   `https://github.com/<owner>/<repository>/.github/workflows/sign-authenticity-request.yml@refs/heads/main`
   for this public repository and set `authenticity.signingConfigured` to `true`
   while leaving `bootstrapComplete` set to `false`. Use the exact owner and
   repository spelling emitted in the certificate; do not use patterns or wildcards.
6. Run the signing workflow only from protected `main`. Download its artifact,
   verify the request and bundle locally with Cosign `v3.0.6`, and add only the
   matching `authenticity/authenticity-request.sigstore.json` through a pull
   request. The workflow does not push or deploy.
7. Replace the empty `clinical-safety`, `security`, and `operations` usernames in
   `release-control-policy.json`. Only after the genuine bundle is committed and
   passes repository policy, set `bootstrapComplete` to `true` through a final
   reviewed pull request. A person may belong to only one release role.

## Protected main branch

Require pull requests, two approvals, dismissal of stale approvals, approval of
the most recent push by someone other than its author, conversation resolution,
`required_status_checks.strict: true`, and exactly the
`validate-pull-request` status check bound to the GitHub Actions app from
`Validate public release control`,
administrator enforcement,
and linear history. Deny force pushes and deletion. Do not permit bypass actors.
After the one-time initial bootstrap, disable direct pushes to `main` for users,
administrators, and automation. Every later workflow or trusted-code change must
arrive through a pull request validated by verifier bytes from the base commit.
The push check also uses the previous `main` verifier, but this is defense in
depth and does not replace branch protection against staged direct pushes.

Rotate the complete ten-file trusted-code bundle with the three separate pull
requests documented in the root README. Stage all three workflows, all six
Python verifier/helper/test files, and `docs/published-python-controls.json` as
non-executable bytes under `trust/next` with a complete staged mapping; merge;
promote exactly that whole staged bundle while retaining it; merge; then remove
only staged metadata and the staged tree. Never execute candidate or staged
files, promote a subset, combine stage with promotion, or use a direct push for
rotation.

The initial hardened trust manifest may carry `bootstrapRecovery`. Treat it as
lineage-scoped authorization for exact recovery to the committed known-base
snapshot, not as globally persistent one-time state. Promotion consumes it and
it cannot be re-added by cleanup or a later transition in that hardened
lineage. Exact recovery returns to the fail-closed manifest-less published
state. Reapplying the hardening from that state is a new bootstrap: repeat the
full protected pull-request process with two approvals and all required checks,
then establish a new hardened lineage and its new recovery authorization.

## Environments

Create static `staging` and `prod` environments. For each environment:

- add accountable required reviewers and enable prevent self-review;
- allow deployments only from the protected `main` branch;
- disable administrator bypass;
- store only `DEPLOY_HOST`, `DEPLOY_USER`, `DEPLOY_SSH_PRIVATE_KEY`, and
  `DEPLOY_KNOWN_HOSTS` as environment secrets; and
- use a distinct least-privilege SSH key and target account per environment.

No repository or organization deployment secret is permitted.

## Host boundary

Provision `/usr/local/libexec/link/deploy-approved-release` as root-owned,
non-writable by the SSH principal, and executable only through a constrained
command or tightly scoped `sudoers` rule. The agent must map artifact digests to
fixed private registry repositories, verify signatures and attestations, enforce
staging-to-production digest identity, serialize deployments, run health and
rollback controls, and retain detailed evidence in protected storage. It emits
only `RELEASE_DEPLOYMENT_SUCCEEDED` on success.

The agent interface receives both canonical authenticity bindings as
`--release-set-manifest-sha256` and `--combined-identity-sha256`, in addition to
the release, artifact, evidence, and promotion hashes. It must reject missing,
malformed, or unexpected values and must not substitute one binding for the
other.

Do not place registry credentials in this public repository. Keep them managed
on the host or in an approved private secret manager.

## Cutover evidence

Before every production cutover, independently export and review branch
protection, environment reviewer and bypass settings, environment secret names,
workflow SHA pins, role mappings, and denied bypass tests. Repository owners can
change hosted settings, so checked-in policy alone is not sufficient evidence.
Audit the branch-protection API response and retain evidence that
`required_status_checks.strict` is `true`, that the sole required check context
is exactly `validate-pull-request`, and that its app binding is GitHub Actions;
a matching unbound context or a check produced by another app is insufficient.
Include the authenticity workflow identity, OIDC issuer, workflow permissions,
Cosign version, canonical request digest bindings, and bundle verification in
that independent review.
