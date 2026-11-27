import type { GuideTopic } from "../types";

/** app/core/access_gate.py, app/services/terms_service.py, app/services/terms_copy_service.py, app/services/passwords.py, app/cli/reset_admin.py. */
export const firstSignIn: GuideTopic = {
  slug: "first-sign-in",
  title: "First sign-in and a lost password",
  summary: "The new password at first sign-in, the licence agreement every administrator accepts for the organisation (and its emailed copy), the terms of use for everyone else, and getting back in when the administrator's password is lost.",
  sections: [
    {
      id: "open-hawk",
      title: "Open Hawk AI",
      blocks: [
        {
          kind: "p",
          text: "Open the address the installer printed: `https://HAWK_HOST:PORT` (for example `https://localhost:3000`), or `PUBLIC_URL` when it is set. Until a certificate of your own is in use, the browser warns once (\"Your connection is not private\": Advanced, then continue). [HTTPS](/settings/guide/https) explains how to put a trusted certificate in place.",
        },
        {
          kind: "p",
          text: "Sign in with your email and password: there is no workspace to type, since an email address belongs to one account on the installation. The page is light; anyone can switch to dark, or to their device's setting, under **Appearance** in the account menu (top right), and the choice is kept in that browser. An Owner or Admin sets everyone's default look on [Settings → Branding](/settings/branding).",
        },
        {
          kind: "p",
          text: "A new installation works for 3 days from its first start. Owners and admins see the time left in a banner at the top of every page: before it runs out, download the licence request under [Settings → Licence](/settings/activation), send it to Bhawani Singh and upload the `.hawkai` licence you receive ([Licence](/settings/guide/licence)).",
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
      title: "The licence agreement, and the terms of use for everyone else",
      blocks: [
        {
          kind: "steps",
          items: [
            "Right after choosing their password, an owner or admin is shown Hawk AI's End User Licence Agreement (the licence, its limits of liability, the AI disclaimers, the features and the terms of use). They read it to the end, tick \"I have read\", give the company's legal name, their own full name and email (filled in from their account, and editable), and confirm they accept on behalf of the company and are authorised to.",
            "Until the first administrator has accepted, Hawk AI is closed to everyone and background work does not run; others see \"An administrator must accept the terms of use before Hawk AI can be used.\" Every other owner or admin accepts the agreement the same way at their own next sign-in.",
            "Everyone else accepts the shorter terms of use for users (Schedule 2 of the agreement) before they first use Hawk AI: no company details are asked.",
            "Acceptance is tied to the exact text: its version and SHA-256. A new version of the agreement, or a change to the licensor's details in `deploy/.env` (`LICENSOR_LEGAL_NAME`, `LICENSOR_ADDRESS`, `LICENSOR_NOTICE_EMAIL`, `GOVERNING_LAW`, `DISPUTE_FORUM`, `LIABILITY_CAP_NO_FEES`), is asked for again.",
          ],
        },
        {
          kind: "p",
          text: "Each acceptance is kept for good: who accepted, for which company, the version and its SHA-256, the time, the address and the browser. Nobody can change or delete it; it is in the audit log and in the auditor's export.",
        },
        {
          kind: "p",
          text: "A copy of the agreement goes to the administrator's email: the full text in the email, the exact accepted text attached (.txt, whose SHA-256 is the recorded one) and an .html copy with the acceptance details. Hawk AI runs on your server, so the email server is often set up later: the copy waits, and goes out as soon as a test of the email server passes (Settings → Email (SMTP)), or within five minutes after. Failed sends are tried again, waiting longer each time. Settings → About shows \"Copy emailed to … on …\" or \"Will be emailed when the mail server is set up\", and owners and admins can email it again or download it there.",
        },
        {
          kind: "p",
          text: "For an automated setup, `ACCEPT_TERMS` set to the deploying person's email in `deploy/.env` accepts the agreement for the organisation and everyone using this installation, recorded under that name (with `ORGANISATION_NAME` as the company), and its copy is emailed to them.",
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
