# Release set authenticity

`authenticity-request.json` is the immutable, canonical request for the approved
release set. Its bytes are sorted, compact JSON followed by one LF newline.
The request is public metadata and contains digests only.

`authenticity-request.sigstore.json` is optional. When present, it must be the
Cosign bundle produced by `Sign release set authenticity request` for the exact
request bytes and must verify against the exact certificate identity and OIDC
issuer configured in `release-control-policy.json`.

The checked-in policy is intentionally unconfigured. Keep `bootstrapComplete`
false while replacing the placeholder with the literal public repository
workflow identity, enabling signing, running the workflow, and committing its
verified bundle. Set bootstrap complete only afterward. Never use a regular
expression, wildcard, private repository, or locally generated key.

Verify locally with:

```bash
python3 scripts/verify_authenticity.py \
  --request authenticity/authenticity-request.json \
  --policy release-control-policy.json
```

Add `--bundle authenticity/authenticity-request.sigstore.json` after a genuine
keyless bundle has been produced. The verifier requires Cosign `v3.0.6` for
cryptographic bundle verification.
