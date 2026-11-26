import type { GuideTopic } from "../types";

/** app/services/mailer.py, Settings → Email (SMTP), deploy/.env.example. */
export const email: GuideTopic = {
  slug: "email",
  title: "Email (SMTP)",
  summary: "One email server for everything Hawk AI sends: where to set it, why nothing is sent until it is tested, and what sends email.",
  sections: [
    {
      id: "set-up",
      title: "Set up the email server",
      who: "Owners and admins",
      blocks: [
        {
          kind: "steps",
          items: [
            "Open [Settings → Email (SMTP)](/settings/email). Give the server, its port (587 with STARTTLS, or 465 with implicit TLS), the sign-in if it needs one, and the From address and name. It saves as you type; the password is kept encrypted and never shown again (\"Kept: type to replace\").",
            "Test it: **Test connection**, or **Send test email** (to you by default). Either one counts as tested.",
            "Leave the certificate check on. For a mail server with a private CA, trust that CA under [Settings → Network & proxy](/settings/network) instead.",
          ],
        },
        {
          kind: "note",
          tone: "info",
          text: "Nothing is sent for sign-in, people, support or hands-off until the settings in force have been tested. Changing any of them asks for a new test. The last settings that worked are kept.",
        },
        {
          kind: "p",
          text: "A password is never sent without encryption: without TLS from the start, the server must offer STARTTLS. Email always goes directly to the mail server, never through the company web proxy.",
        },
      ],
    },
    {
      id: "from-deploy-env",
      title: "Or from deploy/.env",
      who: "Whoever runs the server",
      blocks: [
        {
          kind: "p",
          text: "Until the page is used, Hawk AI uses these settings from `deploy/.env` (the page's settings win once saved):",
        },
        {
          kind: "table",
          head: ["Setting", "Default", "What it does"],
          rows: [
            ["`SMTP_HOST`", "empty", "The mail server."],
            ["`SMTP_PORT`", "`587`", "Its port."],
            ["`SMTP_SECURE`", "`false`", "`true` for implicit TLS (port 465)."],
            ["`SMTP_USER`", "empty", "The account to sign in with."],
            ["`SMTP_PASS`", "empty", "Its password."],
            ["`SMTP_FROM`", "`SMTP_USER`", "The From address."],
            ["`SMTP_FROM_NAME`", "empty", "The From name."],
            ["`SMTP_REJECT_UNAUTHORIZED`", "on", "`false` stops checking the mail server's certificate (said in the log). Leave it on."],
          ],
        },
      ],
    },
    {
      id: "what-sends-email",
      title: "What sends email",
      blocks: [
        {
          kind: "list",
          items: [
            "Sign-in: \"Forgot your password?\" links and the email saying a password was changed; links for people who join by themselves.",
            "People: the welcome email for someone added, and both addresses when a sign-in email changes.",
            "Get help: each support case or enhancement and every answer, when Get help uses the portal.",
            "Hands-off: the weekly status, and the self-check's emails to owners and admins (a problem found, a problem gone, a support case to forward).",
            "The licence agreement: the copy each administrator gets when accepting it. It waits for the email server and goes out as soon as a test passes.",
            "Backups: a copy of every encrypted backup to the backup mailbox (`BACKUP_EMAIL`), and the \"Hawk AI stopped\" email. These go whenever a mail server is set, tested or not.",
          ],
        },
      ],
    },
  ],
};
