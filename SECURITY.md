# Security and publication rules

Keep secrets, credentials, private runtime data and preservation archives out of Git. Use approved secret stores and inject secrets at runtime. Configuration examples must contain only clear nonsecret placeholders. Do not post suspected secrets in issues, pull requests or logs.

Report a suspected vulnerability privately to the repository owner through an established private channel. No public disclosure address is configured in this bootstrap.

Review dependency manifests and install scripts before installing. Pin dependency versions with the appropriate lockfile. Review CI changes, use minimum job permissions, pin third-party actions, and keep deployment behind reviewed environment controls. No cloud account, deployment target, OIDC trust or secret has been configured by this import.

The local import check verifies approved bytes and Python syntax only. It is not a comprehensive secret scanner, dependency audit, vulnerability assessment or production-readiness certification.
