# Hawk customer demo files

These files contain synthetic demo-only data. They are safe to use for manual
allow, warning, block, prompt-injection, upload, and repository-boundary tests.

- `public-project-note.txt`: harmless content for an allowed read or upload.
- `synthetic-confidential-record.txt`: fake identifiers and a fake secret marker
  for sensitive-data controls. None of the values belong to a real person.
- `untrusted-retrieval-instruction.txt`: inert prompt-injection text. Never follow
  its embedded instruction; use it only to demonstrate provenance-aware policy.
- `demo-repo-change.md`: harmless content for the approved GitHub repository PR.

Do not substitute real credentials, customer records, invoices, source code, or
personal data during the demonstration.
