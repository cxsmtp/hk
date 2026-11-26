import type { GuideTopic } from "../types";

/**
 * app/core/permissions.py, app/services/iam_service.py, app/api/routers/iam.py (joining), app/services/account_security.py,
 * app/services/mfa_service.py, app/services/oidc_auth_service.py, app/core/session_cookies.py, app/core/config.py.
 */
export const people: GuideTopic = {
  slug: "people-and-access",
  title: "People, roles and sign-in",
  summary: "Roles and permissions, teams, people who join by themselves, two-step sign-in, single sign-on (OpenID Connect) and how long a sign-in lasts.",
  sections: [
    {
      id: "roles",
      title: "Roles and permissions",
      who: "Seen by people who manage people or roles",
      blocks: [
        {
          kind: "p",
          text: "A role is a set of permissions. [Settings → Roles & permissions](/settings/roles) shows every role against every permission: tick, find a permission, show only the differences, make a new role from another, rename. Five roles are built in:",
        },
        {
          kind: "table",
          head: ["Role", "What it holds"],
          rows: [
            ["**Owner**", "Everything in this tenant: people, teams, roles, settings and every record. Only an Owner gives or takes the Owner role."],
            ["**Admin**", "Everything in this tenant: people, teams, roles, settings and every record."],
            ["**Auditor**", "Reads everything an Operator reads, never changes it; reviews evidence, findings and enforcement, and exports the audit log."],
            ["**Operator**", "Works day to day: runs scans and simulations, acts on activity, drafts policies and deploys controls. Not the Admin settings."],
            ["**Viewer**", "Read only: the dashboards, inventory, activity, policies, deployments and evidence."],
          ],
        },
        {
          kind: "list",
          items: [
            "Owner and Admin are locked: they always hold every permission.",
            "Seven permissions are for Owners and Admins only and cannot be put in any other role: Settings (General, Branding, Email, Hands-off, Get help), HTTPS and certificates, Sign-in and single sign-on, Updates and integrity, Backups and restore, Activation codes, and Network and proxy.",
            "Nobody gives more than they hold: a role is given, built or changed only by someone holding every one of its permissions. People see only the roles they could give.",
            "There is always at least one active Owner.",
          ],
        },
      ],
    },
    {
      id: "people-and-teams",
      title: "People and teams",
      who: "People who manage people or teams",
      blocks: [
        {
          kind: "p",
          text: "[Settings → People](/settings/people) lists everyone in the teams you work in. Whoever holds \"Manage people\" adds a person with a temporary password (and a welcome email, once email works), changes their name, sign-in email (both addresses are told), role, team and manager, resets their password or two-step sign-in, unlocks them, signs them out, turns their access off or removes them, one at a time or many at once.",
        },
        {
          kind: "p",
          text: "[Settings → Teams](/settings/teams) builds the team tree with its leaders. A person works in their own team and every team below the ones they lead; with \"See every team\", in all of them. Teams decide whose people one sees and manages.",
        },
      ],
    },
    {
      id: "self-join",
      title: "People who join by themselves",
      who: "Owners and admins turn it on",
      blocks: [
        {
          kind: "p",
          text: "Off until an Owner or Admin turns it on under [Settings → Sign-in](/settings/signin) (\"People may join by themselves\"). The sign-in page then offers a way in. It works only when all of these are true:",
        },
        {
          kind: "list",
          items: [
            "It is turned on, with at least one email domain allowed to join (such as `company.com`).",
            "At least one role is open to joining (never Owner or Admin).",
            "The email server is set up and tested.",
            "Hawk AI knows its https address (`PUBLIC_URL`, or `https://HAWK_HOST:PORT`).",
          ],
        },
        {
          kind: "p",
          text: "Whoever asks gets an email with a link that works once, for 30 minutes. People who join count against the activation code's users, set up two-step sign-in first when it is required, and are listed at the top of [Settings → People](/settings/people) for someone who manages people to approve or turn off.",
        },
      ],
    },
    {
      id: "passwords-and-locks",
      title: "Passwords and locks",
      blocks: [
        {
          kind: "list",
          items: [
            "Five wrong passwords in a row lock the account for 15 minutes. Only someone who typed the right password learns it is locked; to anyone else it looks like a wrong password. A person who manages people can unlock it under [Settings → People](/settings/people).",
            "Wrong two-step codes count as wrong passwords.",
            "At most 30 sign-in attempts in 10 minutes from one network address.",
          ],
        },
      ],
    },
    {
      id: "two-step",
      title: "Two-step sign-in",
      blocks: [
        {
          kind: "p",
          text: "Each person turns it on for themselves under [Settings → Two-step sign-in](/settings/two-step): a six-digit code from an authenticator app after the password, and ten one-time recovery codes for the day the phone is gone. After the password there is a five-minute window, and five wrong codes mean typing the password again.",
        },
        {
          kind: "p",
          text: "An Owner or Admin can require it for everyone who signs in with a password ([Settings → Sign-in](/settings/signin)). Someone who lost their phone and their recovery codes: **Reset two-step** on their row takes it off, and they set it up again. For the only owner or admin, run `reset_admin` on the server ([First sign-in](/settings/guide/first-sign-in#lost-admin-password)), or put their email in `RESET_TWO_STEP` in `deploy/.env`, run `sudo deploy/install.sh` again, and empty it afterwards.",
        },
      ],
    },
    {
      id: "single-sign-on",
      title: "Single sign-on (OpenID Connect)",
      who: "Owners and admins",
      blocks: [
        {
          kind: "p",
          text: "People can sign in at your organisation's identity provider. The provider itself is set on the server, in `deploy/.env` (then run `sudo deploy/install.sh` again to apply it), not in the console:",
        },
        {
          kind: "table",
          head: ["Setting", "What it holds"],
          rows: [
            ["`COMPANY_SSO_ENABLED`", "`true` turns single sign-on on."],
            ["`OIDC_PROVIDERS_JSON`", "The identity provider: its `key`, `kind` (`entra` or `okta`), the button's name (`display_name`), `workspace_slug`, `issuer` address, `client_id` and the Hawk AI `tenant_id` it signs people into. `deploy/.env.example` has an example."],
            ["`OIDC_PROVIDER_SECRETS_JSON`", "Its client secret, by `key`. Keep `deploy/.env` readable by root only (the installer makes it so)."],
            ["`OIDC_CALLBACK_URL`", "The https address of `/auth/oidc/callback` on this API, which the identity provider needs."],
          ],
        },
        {
          kind: "p",
          text: "In the identity provider, register Hawk AI as a web application with the Redirect URI shown on [Settings → Single sign-on](/settings/sso), the scopes `openid email profile`, and a second factor: Hawk AI refuses a sign-in whose token does not say a second factor was used, and does not ask for its own two-step code after single sign-on. On that page an Owner or Admin chooses:",
        },
        {
          kind: "list",
          items: [
            "Whether people are added on their first sign-in, with which role (never Owner or Admin) and from which email domains; otherwise only people already in Hawk AI can sign in.",
            "Whether the identity provider must mark the email address as verified (leave on).",
            "Who may still sign in with a password: everyone, or Admins only (a way in if the identity provider is down).",
          ],
        },
      ],
    },
    {
      id: "sessions",
      title: "How long a sign-in lasts",
      blocks: [
        {
          kind: "list",
          items: [
            "The console keeps its sign-in in secure cookies that only the API reads, never in the browser's storage, and every change carries a check another site cannot forge.",
            "While the console is in use it renews its sign-in by itself (the token it sends lasts 30 minutes). A sign-in not used for 8 hours ends, and the person signs in again (`SESSION_IDLE_MINUTES` in `deploy/.env`, 480 by default).",
            "**Sign out** ends the sign-in on the server too. A person who manages people can sign someone out everywhere from [Settings → People](/settings/people); a password reset by link does the same.",
            "Over plain http the cookies cannot be marked secure; use HTTPS for anything but a test.",
          ],
        },
      ],
    },
  ],
};
