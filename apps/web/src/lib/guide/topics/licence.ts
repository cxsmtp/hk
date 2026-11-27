import type { GuideTopic } from "../types";

/** app/services/activation_service.py, app/core/licence_gate.py, app/api/routers/licence.py, Settings → Licence. */
export const licence: GuideTopic = {
  slug: "licence",
  title: "Licence",
  summary: "The 3-day trial every installation starts with, the installation ID, the licence request, the .hawkai licence file, the banner and the deactivation page.",
  sections: [
    {
      id: "trial",
      title: "The 3-day trial",
      blocks: [
        {
          kind: "p",
          text: "Every installation of Hawk AI works for **3 days (72 hours)** from its first start, without a licence. After that it needs a licence made for that installation by the owner of Hawk AI, imported as a `.hawkai` file. An installation upgraded from an earlier version gets its 3 days from the upgrade.",
        },
        {
          kind: "list",
          items: [
            "During the trial, owners and admins see a banner at the top of every page with the time left. With a licence, the banner comes back in its last 30 days.",
            "Setting the server's clock back or forward does not lengthen the trial: Hawk AI never goes back to an earlier time than it has seen, and the trial also ends once 72 hours have been seen to pass.",
            "Without a licence for several tenants, Hawk AI serves one tenant, with no cap on its users.",
          ],
        },
      ],
    },
    {
      id: "installation-id",
      title: "The installation ID and the licence request",
      who: "Owners and admins",
      blocks: [
        {
          kind: "p",
          text: "Each installation is given a random installation ID the first time it starts, such as `HK-ABCD-EFGH-JKLM-NPQR`. [Settings → Licence](/settings/activation) shows it with a **Copy** button, the trial's start and end, and the licence in force with how long is left.",
        },
        {
          kind: "p",
          text: "**Download licence request** saves a small `.hawkai-request` file: the installation ID, the server's name and public address, the version and your organisation's name. Nothing secret is in it. Send it to Bhawani Singh, who makes the licence for this installation.",
        },
      ],
    },
    {
      id: "import",
      title: "Upload the .hawkai licence",
      who: "Owners and admins",
      blocks: [
        {
          kind: "p",
          text: "On [Settings → Licence](/settings/activation), choose the `.hawkai` file you received and click **Upload .hawkai licence**. It is checked here, offline, from its signature: nothing is sent anywhere. What it unlocks is in force at once.",
        },
        {
          kind: "list",
          items: [
            "A licence works only on the installation whose ID it names: one for another installation is refused, with both IDs in the message.",
            "Also refused: a file changed after it was signed, an expired licence, a licence issued before the one in force, a file that is not a `.hawkai` licence, and any file over 16 KB.",
            "A licence may also allow several tenants: how many, and optionally how many active users each may have. Tenants and users already there are never removed or turned off; above a cap, new ones are refused, including people who join by themselves.",
            "Every licence uploaded or refused is in the audit log and in the list on the page.",
            "Only the owners and admins of the server's first workspace upload a licence; the admins of other workspaces see it, read only.",
          ],
        },
      ],
    },
    {
      id: "deactivated",
      title: "When it has stopped",
      blocks: [
        {
          kind: "list",
          items: [
            "Once the trial is over without a licence, or the licence has expired, every page shows that the product has been deactivated, whom to contact, and the installation ID with its **Copy** button. The API answers every other request the same way, and background work stops.",
            "Nothing is deleted. An owner or admin of the server signs in on that page, downloads the licence request if needed, and uploads the `.hawkai` licence: everything comes back as it was.",
            "The health checks, first-run setup, signing in and the licence itself stay open, and so does Let's Encrypt's renewal check.",
          ],
        },
        {
          kind: "note",
          tone: "info",
          text: "The licence and the trial are kept in the database and checked each time they are read: a date or an installation ID changed by hand counts for nothing (a changed installation ID gets a new ID, without a trial).",
        },
      ],
    },
  ],
};
