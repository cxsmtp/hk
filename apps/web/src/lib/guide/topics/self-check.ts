import type { GuideTopic } from "../types";

/**
 * app/services/self_check.py, app/services/watchdog.py, app/services/hands_off.py, app/services/support_desk.py,
 * app/api/routers/support.py, Settings → Hands-off, Settings → Get help, deploy/.env.example.
 */
export const selfCheck: GuideTopic = {
  slug: "self-check-and-help",
  title: "Self-check, hands-off and Get help",
  summary: "How Hawk AI checks and repairs itself, the weekly status email you can answer with one word, support cases, and MAINTAINER_EMAIL.",
  sections: [
    {
      id: "self-check",
      title: "The self-check",
      blocks: [
        {
          kind: "p",
          text: "Every 5 minutes (`WATCHDOG_EVERY_SECONDS`, 300) Hawk AI checks itself: the database, Redis, the worker and the scheduler, the email server once tested (it signs in but sends nothing), each connector that can sign in and read, the automatic runs it relies on (backups, the monitoring checks, the daily snapshot pack), and more than 30 errors in 15 minutes. [Settings → Backups & health](/settings/backups) and [Settings → Hands-off](/settings/hands-off) show what it found, with **Check now**.",
        },
        {
          kind: "steps",
          items: [
            "A problem seen once is noted, and Hawk AI tries to put it right: the last working connector settings, signing in to Checkmarx One again, the mail server again after a pause.",
            "Seen on the second check in a row, the owners and admins get an email.",
            "On the third, if auto-update is on and the server reached the internet on its last update check, a support case is raised by itself and the email asks an administrator to forward it to the maintainer.",
            "When the problem clears, whoever was told hears so.",
          ],
        },
        {
          kind: "p",
          text: "A version installed less than a day ago that broke what worked before is put back to the previous version, once, when the updater looks after the services. An outage on the far side (a service down or slow) is never blamed on it.",
        },
        {
          kind: "p",
          text: "Under the self-check, **This server** lists what `deploy/install.sh` found on the machine itself the last time it ran, each as Pass or Check: a firewall, SSH root sign-in and passwords, automatic security updates, time synchronisation, disk encryption and the audit daemon (items of the CIS Linux benchmark auditors ask about). Hawk AI only reports them and changes nothing on the machine: put one right, then run `sudo deploy/install.sh` again to refresh the list.",
        },
      ],
    },
    {
      id: "maintainer-email",
      title: "MAINTAINER_EMAIL",
      who: "Whoever runs the server",
      blocks: [
        {
          kind: "p",
          text: "Hawk AI never sends anything outside your organisation by itself. Set `MAINTAINER_EMAIL` in `deploy/.env` to the address of whoever supplied Hawk AI: the self-check's emails then name it as where to forward a support case. Without it, the email says to forward it to the maintainer. There is no default.",
        },
      ],
    },
    {
      id: "hands-off",
      title: "Hands-off: a weekly status you can answer",
      who: "Owners and admins",
      blocks: [
        {
          kind: "p",
          text: "On [Settings → Hands-off](/settings/hands-off), choose who gets a short status email once a week, and the day and hour (server time; Monday at 08:00 until changed). It needs a tested email server. Its buttons ask \"Yes, do it\" before they act, so nobody has to sign in.",
        },
        {
          kind: "p",
          text: "With replies turned on, Hawk AI reads the mailbox it sends from (IMAP) every 2 minutes (`INBOX_EVERY_SECONDS`, 120) and acts on a reply that starts with one word:",
        },
        {
          kind: "table",
          head: ["Reply", "What it does"],
          rows: [
            ["`PAUSE`", "Pause the weekly status for 7 days (or `PAUSE 14` for 14)."],
            ["`RESUME`", "Resume after a pause."],
            ["`RUN`", "Run the monitoring checks that are due now."],
            ["`STATUS`", "Send the status now."],
            ["`STOP`", "Stop sending the status to this person."],
            ["`SOLVED`", "Close the case the email is about."],
          ],
        },
      ],
    },
    {
      id: "get-help",
      title: "Get help: support cases and enhancements",
      blocks: [
        {
          kind: "p",
          text: "Everyone can raise a support case or an enhancement request from **Get help** in the main menu and follow it there. Each gets a number (`SUP-0001`, `ENH-0001`) and moves through New, In progress, Waiting for reply, Completed or Declined. When the person who raised it answers, a request waiting for them goes back to In progress, and a closed one is reopened. At most 20 requests an hour per person.",
        },
        {
          kind: "p",
          text: "The owners and admins of the tenant (and whoever holds \"Answer support cases & enhancements\") answer them, and get an email for each new one once email works.",
        },
      ],
    },
    {
      id: "get-help-settings",
      title: "Where requests go",
      who: "Owners and admins",
      blocks: [
        {
          kind: "list",
          items: [
            "[Settings → Get help](/settings/help) chooses between the **Support portal in Hawk AI** (the default: a form, a numbered queue and email updates through the tested email server) and **Email**: Get help opens each person's own email app, addressed to the address given, for a server that cannot send email out of its network. By email nothing is stored in Hawk AI.",
            "`SUPPORT_MODE=email` with `SUPPORT_EMAIL` in `deploy/.env` sets the default when the server starts; a choice made on the page wins.",
          ],
        },
      ],
    },
  ],
};
