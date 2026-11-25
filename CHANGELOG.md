# Hawk AI version log

Every release, newest first: the version shown bottom-left in the console (HK-xx.xx.xx, from the VERSION file), when it was merged, and what changed for the people using it. Updated with every change merged to main (CLAUDE.md).

## HK-00.02.00 — pending · [#NN](https://github.com/cxsmtp/hk/pull/NN)

- **Updates from the console.** Settings → Updates (owners and admins) lists every published version of Hawk AI, newest three first and ten more at a time, and installs a newer one or rolls back to an older one in one click.
- **An update never loses the version that ran.** The new updater service takes a backup, installs every image, brings the database up to date and starts each service in order; if Hawk AI is not healthy within 150 seconds, it puts the previous version back by itself, with the database as it was before the update.
- **A version that failed is never installed again by itself.** Auto-update is off until an owner or admin turns it on; it then looks a minute after start and every 15 minutes, follows the latest or the stable release, waits for an hour of the day if one is chosen, and says on the page what it found.
- **Only what was released is installed.** Every image carries a signed list of its files; Hawk AI checks its own files and that signature at start, every 6 hours and on Check now, and shows Genuine, Files changed, Not signed by the release workflow, Not confirmed yet or Development copy, with an alert for owners and admins when something is wrong.
- **Releases are built and signed by GitHub.** A release workflow publishes the api, web, proxy and updater images for amd64 and arm64 with a build attestation; a stable release is promoted by hand, without rebuilding.
- **Status.** Not merged yet: the test results and the load test comparison are added to this entry when it is.

## HK-00.01.00 — 2026-11-25 13:56 UTC · [#2](https://github.com/cxsmtp/hk/pull/2)

- **Activation codes.** Hawk AI works until 31 January 2027 without a code; a product activation code from the maintainer keeps it working, and a tenants code allows several tenants. Codes are checked offline, from their signature.
- **A clear page when it stops.** After the end date every page says the product has been deactivated, and nothing is deleted; administrators see a banner before that.
- **One-command install.** `sudo deploy/install.sh` checks Docker, makes the data folder and its secrets, starts every service and prints the first administrator's sign-in once.
- **The version on every screen.** The version is shown bottom-left as HK-xx.xx.xx and returned by the API's health check.
- **Status.** Merged with the API and console tests passing.

## HK-00.01.00 — 2026-11-25 08:32 UTC · [#1](https://github.com/cxsmtp/hk/pull/1)

- **Hawk AI, under its own name.** The product is called Hawk everywhere, with a proprietary licence, and the code no longer names other people or their machines.
- **Status.** Merged with the tests passing. The version was not bumped for this change: the version log starts with #2.
