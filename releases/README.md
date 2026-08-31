# Release manifests

Commit one JSON manifest per approved candidate. Use a filename matching the
manifest release ID, for example `rel-20260720t120000z-a1b2c3d4e5f6.json`.

Manifests contain only opaque hashes and timestamps, including bindings to the
private source-review and clinical-safety evidence. Never add image repository
names, hostnames, IP addresses, clinical data, evidence contents, logs, user
identifiers, or secrets.

Production manifests must bind the SHA-256 of the exact staging manifest and
must retain the same source commit, artifact digests, and authenticity bindings.

Both staging and production manifests require these exact canonical request
bindings:

```json
{
  "releaseSetManifestSha256": "7c9a35f00c3b23457f47736ddb3eaabe66195cd829e2ca360a922c14a05c509e",
  "combinedIdentitySha256": "891e8cad0ff697f62a7929e83dd4cd9db7a7f522ed0b3bb05a78f45e39d771d7"
}
```

Do not reuse either value with another authenticity request or combine values
from different requests. Validate the complete document against
`schemas/release-manifest.schema.json` and `scripts/verify_release.py`.
