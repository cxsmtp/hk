# OIDC SSO v1 deployment note

> Imported reference documentation from the selected original worktree. Prior deployment, version and test claims below are historical source context, not current acceptance. See [the collaboration README](../../README.md) for verified results and remaining limits. Commands require an isolated, explicitly configured environment.


Hawk’s v1 enterprise sign-in supports configuration-backed authorization-code
PKCE for one tenant-specific Microsoft Entra ID authority and one Okta issuer.
The provider record contains only the provider key, kind, display name,
workspace slug, exact HTTPS issuer, and client ID. Client secrets are stored in
the separate encrypted secret configuration. A sign-in succeeds only when the
validated issuer and `sub` match one configured binding to an existing active
Hawk user and tenant membership; email claims never link or create accounts,
and database membership supplies the role.

The deployment must provide fixed HTTPS callback and frontend completion URLs.
`COMPANY_SSO_ENABLED` fails hardening when provider records, encrypted secrets,
callback/frontend URLs, or exact bindings are malformed, duplicated,
cross-tenant, or incomplete. Entra authorities must use the tenant-specific
issuer; `common`, `organizations`, and `consumers` authorities are rejected.
The ID token must be RS256, have the exact issuer and audience, valid `exp`,
matching nonce and subject, and include `amr` with `mfa`. Microsoft’s optional
claims configuration is required to emit `amr`; it is not proof that a real
tenant has been configured.

The callback exchanges the code through the pinned outbound transport with
redirects disabled. Short-lived state and completion tickets are encrypted,
browser-bound, and atomically consumed in Redis. The browser receives only a
short-lived completion ticket in a URL fragment; the callback page removes the
fragment before completing the ticket, and Hawk access or refresh tokens never
appear in a URL or log.

Provider setup references:

- [Microsoft optional claims](https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims)
- [Microsoft optional claims reference](https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims-reference)
- [Microsoft v2 authorization code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)
- [Okta ID token validation](https://developer.okta.com/docs/guides/validate-id-tokens/main/)
- [Okta authorization code with PKCE](https://developer.okta.com/docs/guides/implement-grant-type/authcodepkce/main/)

This batch has no selected production tenant credentials and no live federation
acceptance. SCIM, SAML, group role mapping, offboarding, logout/revocation,
break-glass, and live MFA proof remain outside v1 local evidence.
