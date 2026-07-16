# Security and data handling

COE has three distinct asset classes. They must not be merged into one portable archive.

1. The application bundle contains code, schemas, examples, and deployment scripts. It contains no patient data, credentials, license files, or terminology payloads.
2. The terminology bundle contains licensed reference indexes for controlled internal use. It is not a public redistribution artifact.
3. Patient inputs and every protected-run output remain on the authorized machine in access-controlled, encrypted storage. Protected output is treated as PHI even when it contains only aggregate codings.

## Required runtime boundary

- Install dependencies and any approved model weights before mounting patient data.
- Run analysis without network access or telemetry. A process-specific Windows firewall rule is defense in depth; protected native runs require host/VM-wide egress denial or equivalent isolation.
- Mount patient inputs and terminology indexes read-only. Use a separate restricted writable run directory.
- Never place raw inputs, paths, document identifiers, snippets, phrases, hostnames, usernames, IP addresses, or credentials in support reports.
- Never silently fall back from a requested CUDA run to CPU.
- Exact lexical matching is intentionally CPU/SQLite. A GPU is used only by an explicitly enabled semantic stage.
- Keep acceptance and publication disabled. Candidate generation is not a clinical decision.

## Protected-local gate

A protected run requires a machine-readable data-use attestation naming the approval, retention policy, and output classification. The application validates that the approval is affirmative and that the output classification remains restricted. The example attestation is a template, not an approval.

The local JSON is unsigned and reusable, so it is a procedural fail-closed gate rather than proof of authorization. An authorized operator must verify that its references still bind to the exact corpus, purpose, host, and validity window before each protected run.

## Reporting a problem

Stop the run and preserve only sanitized diagnostics. Do not attach patient files, licensed terminology payloads, database files, access-check logs, cookies, tokens, `.env` files, RDP files, or SSH material to an issue or support request. Rotate any exposed credential or session token before resuming work.
