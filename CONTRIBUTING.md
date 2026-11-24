# Development workflow

Use the component branches listed in README as integration lanes. Create short-lived feature branches from the relevant lane; send reviewed pull requests back to that lane and then to main. Include shared dependency changes in the same review or explicitly linked dependency pull requests.

Every pull request must state its source lineage, behavior change, dependency and configuration changes, tests run, tests not run, and rollback approach. Keep product readiness separate from repository setup. Do not claim a feature works solely because its files are present.

Before merging: review the exact diff; check for secrets and runtime/private data; install from reviewed dependency manifests/lockfiles in a clean environment; run the affected component tests and shared API/contract tests. Do not add local virtual environments, node_modules, database snapshots, logs, certificates, credentials or unscreened Git history.

The repository owner should enable required reviews and status checks once the remote is accessible. Those settings are not enabled by adding this document. Changes to repository access, credentials, protected environments or cloud trust require owner approval.
