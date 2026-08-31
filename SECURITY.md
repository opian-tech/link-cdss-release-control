# Security policy

Do not report vulnerabilities in public issues. Use the organization's private
security reporting channel configured for this repository.

This repository is intentionally public and metadata-only. Do not commit source
code, credentials, environment files, private endpoints, logs, raw deployment
evidence, PHI, clinical payloads, or patient, clinician, facility, tenant, or
user identifiers. Immediately revoke and rotate any credential exposed here,
remove public access to the affected data, preserve audit evidence, and follow
the incident response process.

Authenticity signatures must be GitHub Actions OIDC keyless signatures over the
exact canonical request. Certificate verification must use the literal workflow
identity configured in policy and the GitHub Actions issuer. Wildcards, regular
expressions, alternate issuers, local keys, fabricated bundles, and signatures
from private repositories are prohibited.
