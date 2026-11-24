# Repository validation — 23 October 2026

The selected current-worktree collaboration baseline includes native-local and
Docker setup. These results validate the stated fixtures and source; they do not
certify every live provider, OS deployment or production configuration.

| Check | Exact source | Result |
|---|---|---|
| Complete local API unit profile, Python 3.11.15 | Untouched archive `245f7724751483a0abc8dd68ab5e755002898280` | **5,076 passed, 0 failed, 4 deselected**, exit 0, 1,146.80 seconds; finished 06:15:29 UTC. All 105 installed packages passed compatibility checks. |
| TLS/destination-policy regression file | Test SHA-256 `10efbe7f9286d8b75a4ecb220d6d8484a213c8d6255c7953d07c23812981be51` | 45 passed on Python 3.11 Linux and 45 passed on Python 3.12 macOS. Real client SSLContext retains certificate/hostname verification, original SNI and approved-IP assertions. Production code unchanged. |
| Fully native clean installation and runtime | Untouched archive `5ee839812ff8917208f48d2d81bfa65a81e7264a`, no overlays | Fresh API/web/extension locked installs; native PostgreSQL 16.15 and Redis 7.4.11; both migration/seed targets; strict API readiness, real worker/beat heartbeats and compatibility; **10 integration tests**, including all four PostgreSQL cases without skips. Exit 0. |
| Native web acceptance | Same untouched `5ee8398` archive | **272 web tests**, production build, fixture login and eight routes passed; no JavaScript errors or API 5xx. Fresh profile using explicit installed Chrome. Docker was not used. |
| Native bootstrap guards | Published native setup | Nine data/path/version/configuration guard tests passed. Existing data is refused. UTC, TCP-only PostgreSQL and data-directory identity are verified. Four owned service listeners were absent after cleanup. |
| Provenance | Published native setup | Original import/dependency receipts and reviewed hashes pass; 1,367 Python files parse, zero errors. Held simulation changes and private/generated runtime artifacts excluded. |

The API tree object is `97e1b43f672b223578bb049de3c117bb642ce5c6` at both
`245f772` and `5ee8398`. API, web, extension, packages, endpoint and desktop-guard
source/test trees are unchanged between those commits. The latter commit adds
native orchestration, tests and documentation. A later documentation-only commit
does not change the tested application or native runtime bytes.

The full unit command used the existing selection:

```sh
python -m pytest -vv --tb=short tests/ \
  -m "not integration and not e2e and not acceptance" \
  --ignore=tests/integration --ignore=tests/e2e
```

It ran with the documented unit profile, a fresh SQLite database, an allowlisted
environment and synthetic ephemeral settings. Integration and browser acceptance
ran separately with enabled strict readiness against native disposable services.
The first native candidate inherited a non-UTC database timezone and failed three
integration assertions; explicit UTC in a fresh cluster passed all ten unchanged
tests. No production authorization or signature guards were relaxed.

## Hosted CI and remaining boundaries

[GitHub API run 39908855560](https://github.com/dang070298/hhaawwkk--aaii/actions/runs/39908855560)
for `5ee8398` did not execute any steps. GitHub reports an account payment or
spending-limit restriction. The owner must resolve Billing & plans before the
same published source can receive hosted-CI acceptance. No billing settings were
changed and blocked jobs were not manually retried. Local passes are not a green
GitHub CI claim.

Earlier matching-source component checks cover extension types/build/143 tests,
SDK build/35 tests, MCP/216 tests, endpoint software/871 tests plus eight subtests,
and desktop-guard/39 tests. Four installed-provider endpoint cases remain unrun.
The extension mock-browser suite now passes all ten tests, with zero skips and
external networking disabled. The approved fresh pull of official Playwright
1.58.2 succeeded. Untouched `7d99da7` initially produced three passes and seven
telemetry failures: its mock sign-in omitted actor identity, while the production
telemetry guard requires a tenant, backend and actor. Supplying a synthetic email
through the normal `authEmail` setting and asserting that attribution corrected
the fixture. No production guard or application code changed. The corrected
fixture SHA-256 is
`461ac0c13375625a23a3c610920c11fdeb82591dcac73ebe753b6519913bd725`.
See the [extension test instructions](../../extension/README.md#playwright-e2e).
Live-backend and provider-account extension E2E remain unverified.

Live provider credentials, installed native hooks/enrollment, production KMS/HSM
signing, production deployment/CD and release upgrade/rollback are not certified.
The simulation transaction-recovery patch remains held outside published source.
Forty-nine historical-only source variants remain preserved/unresolved under the
owner's explicit scope decision. See the source-accounting and native-local guides.

Raw logs, screenshots, generated state, test keys and databases are intentionally
not committed. This document records the reviewed, nonsecret results.
