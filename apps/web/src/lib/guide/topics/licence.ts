import type { GuideTopic } from "../types";

/** app/services/activation_service.py, app/core/licence_gate.py, app/api/routers/licence.py, Settings → Activation codes. */
export const licence: GuideTopic = {
  slug: "licence",
  title: "Licence and activation codes",
  summary: "How long Hawk AI works without a code, the banner before it stops, the deactivation page, and product and tenants codes.",
  sections: [
    {
      id: "without-a-code",
      title: "Without a code",
      blocks: [
        {
          kind: "p",
          text: "Hawk AI works until the end of **31 January 2027** (UTC) without any code. To keep it working after that, an Owner or Admin enters a product activation code from the maintainer; the code says until when it works.",
        },
        {
          kind: "p",
          text: "In the last 30 days, owners and admins see a banner at the top of every page with the date and the days left, until a product code moves the date.",
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
            "Every page shows that the product has been deactivated, and whom to contact, with a field for the activation code. The API answers every request the same way.",
            "Nothing is deleted. Entering a valid product code on that page brings everything back as it was.",
            "Anyone who can open the page can enter a code there, so wrong codes are limited and recorded in the audit log. Only a product code that runs longer than the one in force is taken.",
            "The health checks stay open, and so does Let's Encrypt's renewal check.",
          ],
        },
      ],
    },
    {
      id: "enter-a-code",
      title: "Enter a code",
      who: "Owners and admins",
      blocks: [
        {
          kind: "p",
          text: "Open [Settings → Activation codes](/settings/activation) and paste the code (it starts with `HK1.`). Codes are checked here, offline, from their signature: nothing is sent anywhere. The page lists what is unlocked and every code entered. Owners and admins are told 30 days before a code expires.",
        },
      ],
    },
    {
      id: "tenants",
      title: "Several tenants: the tenants code",
      who: "Owners and admins",
      blocks: [
        {
          kind: "list",
          items: [
            "Without a tenants code Hawk AI serves one tenant, with no cap on its users.",
            "A tenants code names the organisation, how many tenants it may have and, optionally, how many active users each tenant may have.",
            "Tenants and users already there are never removed or turned off by a code. Above a cap, new ones are refused, including people who join by themselves.",
          ],
        },
      ],
    },
  ],
};
