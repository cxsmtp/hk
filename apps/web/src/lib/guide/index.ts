/**
 * The administrator's guide (Settings → Guide): the topics in order, and what the pages, Jump to and the printable
 * file need from them. Content lives in ./topics, one file per topic.
 */
import { audit } from "./topics/audit";
import { backups } from "./topics/backups";
import { email } from "./topics/email";
import { firstSignIn } from "./topics/first-sign-in";
import { https } from "./topics/https";
import { install } from "./topics/install";
import { licence } from "./topics/licence";
import { network } from "./topics/network";
import { people } from "./topics/people";
import { selfCheck } from "./topics/self-check";
import { troubleshooting } from "./topics/troubleshooting";
import { updates } from "./topics/updates";
import type { GuideTopic } from "./types";

export type { GuideBlock, GuideSection, GuideTopic } from "./types";
export { inlineParts, plainText } from "./inline";
export type { InlinePart } from "./inline";

/** Where the guide lives in the console. */
export const GUIDE_HREF = "/settings/guide";

/** For whom the guide is written, and how to read its commands: shown on its first page and in the printed file. */
export const GUIDE_INTRO = [
  "For the IT administrators who install and look after Hawk AI. Everyone signed in can read it; what only owners and admins (or whoever runs the server) can do is marked beside each section.",
  "Commands are typed on the server, in the Hawk AI folder (the one that holds `deploy/`), as root: put `sudo` in front of a command if you are not root. The settings named in `code` go in `deploy/.env`; run `sudo deploy/install.sh` after changing one.",
];

export const GUIDE_TOPICS: readonly GuideTopic[] = [
  install,
  firstSignIn,
  people,
  https,
  email,
  backups,
  updates,
  licence,
  audit,
  network,
  selfCheck,
  troubleshooting,
];

export function guideTopic(slug: string): GuideTopic | undefined {
  return GUIDE_TOPICS.find((topic) => topic.slug === slug);
}

export function guideTopicHref(slug: string, section?: string): string {
  return `${GUIDE_HREF}/${slug}${section ? `#${section}` : ""}`;
}

/** The topics before and after this one, for the links at the foot of a page. */
export function guideNeighbours(slug: string): { previous?: GuideTopic; next?: GuideTopic } {
  const at = GUIDE_TOPICS.findIndex((topic) => topic.slug === slug);
  if (at < 0) return {};
  return { previous: GUIDE_TOPICS[at - 1], next: GUIDE_TOPICS[at + 1] };
}

/** Jump to (Ctrl K): the guide and each of its topics, for everyone signed in. */
export function guideJumpEntries(): { title: string; sub: string; href: string }[] {
  return [
    { title: "Guide", sub: "Settings · Guide · help", href: GUIDE_HREF },
    ...GUIDE_TOPICS.map((topic) => ({ title: `Guide: ${topic.title}`, sub: "Settings · Guide · help", href: guideTopicHref(topic.slug) })),
  ];
}
