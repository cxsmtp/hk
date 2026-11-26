import type { GuideTopic } from "../types";

/**
 * app/services/updates/service.py, app/services/integrity/service.py, app/cli/integrity.py, app/api/routers/updates.py,
 * deploy/install.sh, deploy/compose.yaml (the updater), Settings → Updates.
 */
export const updates: GuideTopic = {
  slug: "updates",
  title: "Updates, rollback and software integrity",
  summary: "Following the latest or the stable release, updating and rolling back in one click, auto-update, what happens when a version does not start, and the integrity check.",
  sections: [
    {
      id: "two-ways",
      title: "Two ways to run Hawk AI",
      who: "Whoever runs the server",
      blocks: [
        {
          kind: "table",
          head: ["`HAWK_RELEASE` in deploy/.env", "How it is updated"],
          rows: [
            ["empty (the default)", "The images are built from the Hawk AI folder. Update with `git pull`, then `sudo deploy/install.sh`. Settings → Updates shows \"Built from this checkout\" and cannot install."],
            ["`latest`, `stable` or a version such as `0.2.0`", "The published images run, with the updater: owners and admins update and roll back from [Settings → Updates](/settings/updates)."],
          ],
        },
        {
          kind: "list",
          items: [
            "The images come from `UPDATE_IMAGE` (default `ghcr.io/cxsmtp/hk`). A private copy needs its name there and a read-only token in `UPDATE_REGISTRY_TOKEN`.",
            "After an update from the page, the installer keeps the version chosen there. To go back to what `HAWK_RELEASE` says, delete `updater/images.env` in `HAWK_DATA_DIR` and run `sudo deploy/install.sh` again.",
            "`HAWK_UPDATER=off` runs the published images without the updater.",
          ],
        },
      ],
    },
    {
      id: "channels",
      title: "Latest or stable",
      who: "Owners and admins",
      blocks: [
        {
          kind: "p",
          text: "Under **This installation follows** on [Settings → Updates](/settings/updates):",
        },
        {
          kind: "list",
          items: [
            "**Latest**: every merged release, as soon as every test has passed.",
            "**Stable**: the release the maintainer promoted after it was looked at. Choose it for production. Every other version can still be installed or rolled back to from the list.",
          ],
        },
      ],
    },
    {
      id: "update-and-roll-back",
      title: "Update or roll back",
      who: "Owners and admins",
      blocks: [
        {
          kind: "p",
          text: "[Settings → Updates](/settings/updates) lists every published version, newest first. **Update now** installs a newer one and **Roll back to this** an older one, the same way:",
        },
        {
          kind: "steps",
          items: [
            "Every image is checked against what the release workflow built and signed: nothing else is installed.",
            "The updater takes a backup, downloads the images, brings the database up to date and starts each service in order.",
            "If the new version is not healthy within 150 seconds (`UPDATE_START_TIMEOUT_SECONDS`), the previous one is put back by itself, with the database as it was before the update.",
            "A version that failed to start is never installed again by itself.",
            "Later, if the new version turns out unhealthy (services not answering, errors piling up), self-recovery goes back to the previous one, once, then checks it is healthy; if not, it asks for the OEM ([Self-recovery](/settings/guide/troubleshooting#self-recovery)).",
          ],
        },
        {
          kind: "p",
          text: "**Restart Hawk AI** on the same page restarts every service without changing the version: each finishes its work and starts again, and people see \"reconnecting…\" for a few seconds.",
        },
      ],
    },
    {
      id: "auto-update",
      title: "Auto-update",
      who: "Owners and admins",
      blocks: [
        {
          kind: "list",
          items: [
            "Off until an owner or admin ticks **Install new versions by itself**.",
            "It then looks a minute after start and every 15 minutes (`AUTO_UPDATE_EVERY_SECONDS`, 900), for a newer release on the channel followed, and installs it.",
            "**Update by itself only in the hour from**: an hour of the day in the server's time zone (`TZ`). Installing by hand is never held back.",
            "It never installs a version that already failed to start. The page says what it last found.",
          ],
        },
      ],
    },
    {
      id: "integrity",
      title: "Software integrity",
      blocks: [
        {
          kind: "p",
          text: "Every published image carries a signed list of its files. Hawk AI checks its own files against that list, and the list's signature, at start, every 6 hours (`INTEGRITY_CHECK_HOURS`), on **Check now** and before an update. [Settings → Updates](/settings/updates) shows the result; owners and admins see an alert on every page when files changed or the signature is wrong.",
        },
        {
          kind: "table",
          head: ["State", "What it means"],
          rows: [
            ["**Genuine**", "Every file matches the list, and the list is signed by the release workflow."],
            ["**Files changed**", "A file was changed, removed or added since the image was built."],
            ["**Not signed by the release workflow**", "No valid signature for the file list."],
            ["**Not confirmed yet**", "The files match; GitHub could not be asked about the signature yet."],
            ["**Development copy**", "Built from the Hawk AI folder, not by the release workflow: there is no list to check."],
          ],
        },
        {
          kind: "list",
          items: [
            "A server that cannot reach `api.github.com` stays \"Not confirmed yet\". `INTEGRITY_OFFLINE=allow` lets it install updates with the file check alone.",
            "`INTEGRITY_GITHUB_TOKEN`: a GitHub token, only if GitHub's anonymous limit is reached.",
            "On the server: `docker compose -f deploy/compose.yaml exec api python -m app.cli.integrity check --origin` (without `--origin`, only the files, with no network).",
          ],
        },
      ],
    },
  ],
};
