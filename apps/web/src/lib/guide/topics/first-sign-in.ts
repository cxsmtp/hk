import type { GuideTopic } from "../types";

/** app/core/access_gate.py, app/services/terms_service.py, app/services/passwords.py, app/cli/reset_admin.py. */
export const firstSignIn: GuideTopic = {
  slug: "first-sign-in",
  title: "First sign-in and a lost password",
  summary: "The new password at first sign-in, the terms of use for the organisation and for each person, and getting back in when the administrator's password is lost.",
  sections: [
    {
      id: "open-hawk",
      title: "Open Hawk AI",
      blocks: [
        {
          kind: "p",
          text: "Open the address the installer printed: `https://HAWK_HOST:PORT` (for example `https://localhost:3000`), or `PUBLIC_URL` when it is set. Until a certificate of your own is in use, the browser warns once (\"Your connection is not private\": Advanced, then continue). [HTTPS](/settings/guide/https) explains how to put a trusted certificate in place.",
        },
      ],
    },
    {
      id: "new-password",
      title: "Choose your own password",
      blocks: [
        {
          kind: "p",
          text: "Someone signing in with a temporary password (the first administrator's generated one, one set by `reset_admin`, or one given when a person is added) must choose their own before anything else. Nothing else in the console or the API answers until they do.",
        },
        {
          kind: "list",
          items: [
            "At least 12 characters (or what an owner or admin set on [Settings → Sign-in](/settings/signin): a longer minimum, kinds of character to mix, earlier passwords that may not come back).",
            "At most 72 bytes (longer passwords are refused, not cut short).",
            "At least 5 different characters (\"That password is too repetitive\").",
          ],
        },
      ],
    },
    {
      id: "terms",
      title: "Terms of use, for the organisation and for each person",
      blocks: [
        {
          kind: "steps",
          items: [
            "Before anyone can use Hawk AI, an owner or admin accepts the terms of use for the organisation, and gives the organisation's name (unless `ORGANISATION_NAME` set it). Until then Hawk AI is closed to everyone and background work does not run; others see \"An administrator must accept the terms of use before Hawk AI can be used.\"",
            "Then each person accepts them for themselves before they first use Hawk AI.",
            "Acceptance is tied to the exact text: when the terms change, they are asked for again. Every acceptance is in the audit log.",
          ],
        },
        {
          kind: "p",
          text: "For an automated setup, `ACCEPT_TERMS` set to the deploying person's email in `deploy/.env` accepts the terms for the organisation and everyone using this installation, recorded under that name.",
        },
      ],
    },
    {
      id: "lost-admin-password",
      title: "Lost the administrator's password",
      who: "Whoever runs the server",
      blocks: [
        {
          kind: "p",
          text: "On the server, in the Hawk AI folder, set a new temporary password. Hawk AI may be running; it takes the change at once.",
        },
        {
          kind: "code",
          lines: ["docker compose -f deploy/compose.yaml exec api python -m app.cli.reset_admin", "docker compose -f deploy/compose.yaml exec api python -m app.cli.reset_admin someone@company.com"],
          caption: "The first form picks the first active owner or admin (and creates one if there is none); the second names the person.",
        },
        {
          kind: "list",
          items: [
            "It prints the email and a new temporary password to sign in with; they choose their own at sign-in (anyone already signed in as them, at their next click).",
            "Their two-step sign-in is taken off (they set it up again after signing in), and a lock after wrong passwords is cleared.",
            "It is recorded in the audit log.",
            "From inside `deploy/` the shorter `docker compose exec api python -m app.cli.reset_admin` does the same.",
          ],
        },
      ],
    },
    {
      id: "forgotten-passwords",
      title: "Other people's forgotten passwords",
      blocks: [
        {
          kind: "p",
          text: "\"Forgot your password?\" on the sign-in page emails a one-time link to the account's own address. It works once, for 30 minutes, signs the account out everywhere when used, and is followed by an email saying the password was changed. The answer never says whether an address has an account.",
        },
        {
          kind: "p",
          text: "It works only once the email server is set up and tested ([Email](/settings/guide/email)). Who may use it is chosen under [Settings → Sign-in](/settings/signin): everyone with a password, everyone except those who manage people, or nobody (then a person who manages people sets a temporary password under [Settings → People](/settings/people)).",
        },
      ],
    },
  ],
};
