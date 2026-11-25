# Updating without data loss, and going back

Ported from CxMissionZero's docs/updating.md. New versions are applied **without losing data**, from the console or from the command line. Hawk AI is unavailable only for the seconds the new version takes to start, and if it does not come up, the version before is put back by itself, with its data.

## Two channels: `latest` and `stable`

Every release is published as images under several tags: `ghcr.io/cxsmtp/hk-api`, `-web`, `-proxy` and `-updater`. Two of the tags are channels: tags that move as releases come.

| Channel | What it is | When it moves |
| --- | --- | --- |
| `latest` | Every merged release. | Each time a change is merged, once the API tests, the console's checks and the image smoke test have passed. |
| `stable` | The release the maintainer promoted. | Only when the maintainer marks a release as stable, by hand. |

- **`stable` is never a different build.** Promoting rebuilds nothing. `stable` points at the same images, byte for byte, as that release's own tags.
- **How a release becomes stable.** The maintainer runs the **Promote to stable** workflow by hand, with the version (or the commit). It checks that every image is published and that its signature verifies: the one this repository's release workflow made for it, from `main`. Only then does it point `stable` at those images. It never runs on a pull request.
- **A release keeps its own tags.** Each one is also published as its version (for example `0.2.0`, shown in the console as HK-00.02.00) and as `sha-<commit>`. Those never move.
- **Which to use.** `stable` for production, where a release should have been looked at first. `latest` to get every fix as soon as it is merged.
- **Until the first promotion there is no `stable` tag.** A pull of `:stable` then answers `manifest unknown`: use `latest` or a version.

**Run the published images.** In `deploy/.env` set `HAWK_RELEASE` to `stable`, `latest` or a version, then:

```
sudo deploy/install.sh
```

It pulls the images instead of building them, and starts the **updater** with them. Leave `HAWK_RELEASE` empty to build from your checkout (then update with `git pull` and `sudo deploy/install.sh`; the page lists versions but does not install them).

## From the console: Settings → Updates (owners and admins)

No server sign-in after deployment: everything an update needs is on this page.

- **Check for updates** lists every published version: its version, when it was built, its commit, and whether it runs here, is `latest` or `stable`, or failed to start. Times are exact, in your browser's time zone.
  - The versions come from the registry's tags (ghcr.io). Every published version is listed, with no cap. Version tags never change, so what one check reads is remembered: the next check reads only new tags, `latest` and `stable`. The page checks again by itself when it opens and the last check is over 10 minutes old.
  - The page lists the newest 3 versions, then **Load 10 more** at a time.
  - **The image files come from another host.** ghcr.io serves them from `pkg-containers.githubusercontent.com`. If a proxy or firewall blocks it, the page says exactly that, and still lists the versions.
- **Update now** (or **Roll back to this** on an older version) does the rest, through the updater:
  1. Reads the version's images from the registry, by their sha256 digests, and checks each image's signature: the build attestation this repository's release workflow made for it (only what was released is installed).
  2. Downloads every image while Hawk AI keeps running, and checks each one against its digest. A failed download changes nothing.
  3. Checks the new api image's files against their signed list.
  4. Stops the services (each finishes its work), and takes a **backup** with the version that ran (Settings → Backups & health; its reason is "Before the update to HK-…"). Without a backup, nothing is changed.
  5. Brings the database to the new version (the `migrate` service), then starts api, worker, beat, web and proxy on the new images, with the same settings.
  6. Waits until every service is healthy and the new API has said it started. The page follows each step and reloads itself on the new version.
- **A version that does not come up is rolled back by itself.** If it is not healthy within `UPDATE_START_TIMEOUT_SECONDS` (150), or a service stops, the updater removes the new containers, restores the database from the backup of step 4 when the migrations ran, and starts the previous version again. It is recorded under **Recent events** and the version is marked **Failed to start**.
- **Go back to any version.** **Roll back to this** on any older version. Going back to an older version can leave newer data it does not know: if it cannot read the database (its migrations do not know the newer one), it is not started and the version that ran is put back. To go back across a database change, restore the backup taken before the update (Settings → Backups & health, or [deploy/README.md](../deploy/README.md#restore)).
- **Auto-update** (off until an owner or admin turns it on): a minute after the scheduler starts, then every `AUTO_UPDATE_EVERY_SECONDS` (900, 15 minutes), it looks for a newer release on the channel chosen (**This installation follows**: Latest or Stable) and installs it the same way.
  - **Update by itself only in the hour from** limits installing to one hour of the day in the server's time zone (shown next to it, with the server's time now), for example 02:00. Set `TZ` in `deploy/.env` (for example `TZ=Asia/Dubai`) to use your own time zone.
  - The line under the switch says what the last look found: up to date, a release waiting for its hour (outside that hour it still looks once every 55 minutes, so this shows), or what stops it — no updater, or image files this server cannot download.
  - A version that once failed to start is never installed automatically again. By hand it can be tried again.
- **Restart Hawk AI**, and **Download troubleshooting report**: versions, the updater and its last update, recent events, disk, HTTPS mode, the last backup and software integrity; no secrets.
- **Every action is in the audit log** (type **Updates & system**).

**What it needs**
- **The published images and the updater** (`HAWK_RELEASE`, above). The updater looks after the services only while they run Hawk AI's own images (`<UPDATE_IMAGE>-api`, `-web`, `-proxy`); with images built from a checkout, the page says so.
- **Outbound HTTPS** to `ghcr.io` and `pkg-containers.githubusercontent.com` (where GitHub serves image layers), and `api.github.com` (the signatures). Nothing else is sent: the requests carry no data from Hawk AI.
- **A private copy** of the images: `UPDATE_IMAGE=ghcr.io/your-org/your-name` (the images are `<UPDATE_IMAGE>-api`, `-web`, `-proxy`, `-updater`) and `UPDATE_REGISTRY_TOKEN=<a read-only token>`.

| Variable | Default | |
| --- | --- | --- |
| `HAWK_RELEASE` | (none: build from this checkout) | `latest`, `stable` or a version: run the published images, with the updater. |
| `UPDATE_IMAGE` | `ghcr.io/cxsmtp/hk` | Where updates come from. |
| `UPDATE_REGISTRY_TOKEN` | (none) | Only for a private copy: a token that can read it. |
| `UPDATE_START_TIMEOUT_SECONDS` | 150 | How long a new version may take to be healthy before it is rolled back. |
| `AUTO_UPDATE_EVERY_SECONDS` | 900 | How often auto-update looks, once turned on. |
| `INTEGRITY_OFFLINE` | (none) | `allow`: install with the file check alone when `api.github.com` cannot be reached ([software integrity](integrity.md)). |
| `HAWK_UPDATER` | (none) | `off`: no updater, even with the published images. |

## Only what was released is installed

Every release carries a signed list of its files in each image, and each image is signed too. Before installing a version, its images' signatures are checked (made by this repository's release workflow and logged by Sigstore), and the updater checks the new api image's files against their list. Anything else is refused, with the reason. Details, and how to check it yourself: [software integrity](integrity.md).

## The updater

The **updater** is the `updater` service of `deploy/compose.yaml` (`apps/updater`): CxMissionZero's update companion, for a stack of several containers. `deploy/install.sh` starts it with the published images.

**What it does when you click Update now**

| Step | |
| --- | --- |
| 1. Check | The API reads the version's image digests and checks their signatures, then writes the request to `${HAWK_DATA_DIR}/updater/request.json`. |
| 2. Download | The updater pulls every image by its digest while Hawk AI keeps running. A failed download changes nothing. |
| 3. Genuine | It runs `python -m app.cli.integrity check --origin` in a one-off container of the new api image. Files that differ from their signed list, or a list not signed by the release workflow, are refused. |
| 4. Stop and back up | It stops proxy, web, beat, worker and api (each finishes its work), keeps them aside as `<name>-previous`, and runs `python -m app.cli.backup` with the version that ran. |
| 5. Migrate and start | It runs `migrate` on the new image, then creates api, worker, beat, web and proxy on the new images: the same ports, volumes, secrets, environment, limits, security options, restart policy and networks. |
| 6. Check | Every service must be healthy, and the new API must write `ack.json`, within `UPDATE_START_TIMEOUT_SECONDS` (150). Otherwise the new containers are removed, the database is restored from step 4's backup when the migrations ran, and the previous containers are put back under their names and started. |

Once a new version runs, the previous containers are removed (their images stay, to go back to from the page), and the images it chose are written to `${HAWK_DATA_DIR}/updater/images.env`, so a later `sudo deploy/install.sh` keeps them (the page's choice wins, as for HTTPS). Delete that file to go back to what `HAWK_RELEASE` says.

**The trade-off.** The Docker socket can manage every container on the machine, so the updater is kept to one job:
- it opens no port (it has no network at all), and takes no instruction but `request.json`;
- it only ever replaces Hawk AI's own services of its own compose project;
- it replaces them only when they already run Hawk AI's images (`UPDATE_IMAGE`), and only with those images, by digest or by a version, `latest`, `stable` or a commit tag. A request cannot name another image, add a mount or change how a container starts;
- it runs as root for the socket, with no capabilities and no privilege escalation, on a read-only file system.

No other container gets the socket. If you do not want a container with the socket on the machine, set `HAWK_UPDATER=off` and update with `sudo deploy/install.sh`.

## Update from the command line

With `HAWK_RELEASE` set, change it (for example to the next version) and run `sudo deploy/install.sh`; it pulls and restarts. With a checkout: `git pull`, then `sudo deploy/install.sh`. Settings, secrets and data are kept, and the database is migrated before the API starts.

## If something goes wrong

- **Go back to the previous version:** **Roll back to this** on Settings → Updates, or set `HAWK_RELEASE` to the previous version, delete `${HAWK_DATA_DIR}/updater/images.env`, and run `sudo deploy/install.sh`.
- **Before a big upgrade,** download a backup: Settings → Backups & health → **Back up now**, then **Download**.
- **The updater was stopped part-way** (the machine restarted during an update): an update that never finished stops blocking the next one after 30 minutes. If the services are not running, `sudo deploy/install.sh` starts them again; containers left aside are named `…-previous`.
