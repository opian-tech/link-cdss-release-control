# Release set authenticity

`authenticity-request.json` is the immutable, canonical request for the approved
release set. Its bytes are sorted, compact JSON followed by one LF newline.
The request is public metadata and contains digests only.

`authenticity-request.sigstore.json` is optional. When present, it must be the
Cosign bundle produced by `Sign release set authenticity request` for the exact
request bytes and must verify against the exact certificate identity and OIDC
issuer configured in `release-control-policy.json`.

The current hardening PR keeps `signingConfigured` false and retains the exact
`REPLACE_WITH_EXACT_PUBLIC_REPOSITORY_WORKFLOW_IDENTITY` placeholder. After the
hardening is trusted on protected `main`, the next protected PR must set
`signingConfigured` true and replace the placeholder exactly with
`https://github.com/opian-tech/link-cdss-release-control/.github/workflows/sign-authenticity-request.yml@refs/heads/main`.
The verifier permits no other configured identity. Keep `bootstrapComplete`
false while running that workflow and committing its verified bundle. Set
bootstrap complete only afterward. Never use a regular expression, wildcard,
different repository, or locally generated key.

Verify locally with:

```bash
python3 scripts/verify_authenticity.py \
  --request authenticity/authenticity-request.json \
  --policy release-control-policy.json
```

Add `--bundle authenticity/authenticity-request.sigstore.json` after a genuine
keyless bundle has been produced. The verifier requires Cosign `v3.0.6` for
cryptographic bundle verification.
