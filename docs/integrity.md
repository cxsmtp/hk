# Software integrity: is this the code that was released?

Ported from CxMissionZero's docs/integrity.md. Hawk AI checks by itself, all the time, that the code it runs is exactly what this repository's release workflow built, and nothing else.

## How a release is signed

1. **The file lists.** Each image's build writes `integrity.json` (its Dockerfile's `integrity` stage, `infra/scripts/integrity.py`): the SHA-256 of every file it ships, with the version and the commit it was built from.
   - **api** (`/workspace/integrity.json`): `apps/api`, `packages`, `docs/evidence`, `infra/scripts`, `VERSION`, `TERMS.md`, `LICENSE`, `CHANGELOG.md`. The worker and the scheduler run the same image.
   - **web** (`/workspace/integrity.json`): `apps/web` (the built console, not `node_modules` or `.next/cache`), `packages`, `VERSION`.
   - **updater** (`/app/integrity.json`): `hawk_updater`, `VERSION`.
   - **proxy** (`/integrity.json`): the Caddy binary.
2. **The same on every platform.** The release workflow (`.github/workflows/release.yml`) reads each list from the amd64 and the arm64 image it has just published, and stops if they differ. The proxy's list is of a binary built for each platform, so each platform's list is signed instead.
3. **Signed.** It then signs each list and each image with a **GitHub build attestation**. The signing certificate comes from Sigstore and names the workflow, the repository, the branch or tag and the commit. The signature is recorded in Sigstore's public transparency log, where anyone can see it and nobody can remove it. No signing key is kept anywhere that could leak.

## What Hawk AI checks

At start, every 6 hours (`INTEGRITY_CHECK_HOURS`), with **Check now**, and before an update is installed:

- **Files:** every file of the running api image against its list. A changed, missing or added file is found, with no network needed.
- **Who built it:** the list's attestation is fetched from `api.github.com` and checked by the API itself (`apps/api/app/services/integrity/sigstore.py`, a port of CxMissionZero's library-free verifier, using the `cryptography` package Hawk AI already has):
  - the certificate chains to Sigstore's root (`apps/api/app/services/integrity/trusted_root.json`) and was valid when it was used;
  - it was issued to GitHub Actions for `cxsmtp/hk`'s `release.yml`, on main or a version tag;
  - the signature is good and is over this very list;
  - the transparency log recorded it, through its signed timestamp, or an inclusion proof with a signed checkpoint.

  Once confirmed for a list, the answer is kept in the data folder (`integrity-origin.json`), so a server without internet still knows after a restart.
- **Before an update:** each new image's own attestation (by its digest), and the new api image's files against its list (the updater runs `python -m app.cli.integrity check --origin` in it).

**Settings → Updates → Software integrity** shows the result:

| State | Meaning |
| --- | --- |
| **Genuine** | Every file matches, and the list is signed by the release workflow. The panel links the commit, the workflow run and the Sigstore log entry. |
| **Files changed** | Some files differ from what was built. They are listed, and the change is recorded in the audit log. |
| **Not signed by the release workflow** | The files match their list, but no valid signature from this repository's workflow exists for it. |
| **Not confirmed yet** | The files match; GitHub could not be asked yet (`api.github.com` is unreachable). |
| **Development copy** | No file list: a copy built from a checkout, not by the release workflow. |

Owners and admins also see an alert at the top of every page while the state is **Files changed** or **Not signed by the release workflow**.

A release never trusts the activation codes' test key, whatever its settings: an image with a file list is a release (as CxMissionZero's activation does).

## Updates

- **Installing:** a version is installed only when every image's signature checks out and the new api image's files match its signed list.
- A server that cannot reach `api.github.com` can install with the file check alone: set `INTEGRITY_OFFLINE=allow` in `deploy/.env`.

## Check it yourself (one line each)

The files in the running API against their list, and its signature:

```
docker compose -f deploy/compose.yaml exec api python -m app.cli.integrity check --origin
```

An image's signature, with the GitHub CLI:

```
gh attestation verify oci://ghcr.io/cxsmtp/hk-api:latest --owner cxsmtp
```

The file list's signature: copy it out, then check it.

```
docker compose -f deploy/compose.yaml cp api:/workspace/integrity.json integrity.json
```

```
gh attestation verify integrity.json --owner cxsmtp
```

Every attestation is also listed on the repository's **Attestations** page on GitHub, and each signature can be looked up in Sigstore's log at search.sigstore.dev.

## Network

The check asks `api.github.com` over HTTPS (through the proxy when one is set, `HTTPS_PROXY`). With an anonymous limit reached, `INTEGRITY_GITHUB_TOKEN` gives it a token (read-only, public repositories).
