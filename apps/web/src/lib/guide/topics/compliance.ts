import type { GuideTopic } from "../types";

/**
 * app/services/compliance_service.py, app/services/password_policy.py, app/api/routers/compliance.py,
 * app/api/routers/sign_in.py (the password rule, idle sign-out and notice), Settings → Compliance.
 */
export const compliance: GuideTopic = {
  slug: "compliance",
  title: "Compliance (framework packs, DESC, UAE, India)",
  summary: "Framework packs for DPDP, UAE PDPL, DESC ISR, ISO 27001 and 42001, PCI DSS, CIS, NIST, NCA, SAMA, Australia's frameworks, OWASP, MITRE ATLAS and the EU AI Act, with signed evidence; and for DESC, the UAE IA Standard and CERT-In: the sign-in baseline, the clock, retention, data location, SIEM export and the incident report.",
  sections: [
    {
      id: "framework-packs",
      title: "Framework packs",
      who: "Owners, admins and auditors",
      blocks: [
        {
          kind: "p",
          text: "[Settings → Compliance](/settings/compliance) opens on **Framework packs**: one pack per law or standard. Each lists the framework's requirements by their own reference (an article, a clause, a control number) with a short description in our words, who does it, the Hawk AI controls behind it and their status now, worked out from the settings in force and the records kept.",
        },
        {
          kind: "table",
          head: ["Pack", "What it covers"],
          rows: [
            ["DPDP", "India's Digital Personal Data Protection Act 2023 and Rules 2025: Rule 6 safeguards, breach intimation, erasure, Significant Data Fiduciaries' checks on AI software."],
            ["UAE PDPL", "Federal Decree-Law 45 of 2021, with notes on the DIFC and ADGM laws."],
            ["DESC ISR", "Dubai's Information Security Regulation v3 (with the UAE IA Standard and CERT-In): the checklist of the second tab plus the entity's own duties."],
            ["ISO 27001, ISO 42001", "Annex A technological controls; the AI management system's Annex A controls."],
            ["PCI DSS", "v4.0.1 requirements where Hawk AI takes part: card numbers kept out of AI chats, authentication, logs kept 12 months."],
            ["CIS Controls, NIST CSF", "CIS v8.1 safeguards and CSF 2.0 outcomes Hawk AI supports."],
            ["NIST AI RMF, NIST GAI Profile", "All 72 AI RMF subcategories; the 12 generative AI risks of NIST AI 600-1."],
            ["NCA ECC, SAMA CSF", "Saudi Arabia's Essential Cybersecurity Controls (ECC-2:2024) and SAMA's Cyber Security Framework."],
            ["Essential Eight, CPS 234, AU AI Safety Standard", "Australia: ASD's eight strategies, APRA's CPS 234 and the 10 voluntary AI guardrails."],
            ["OWASP LLM Top 10, MITRE ATLAS", "From the tags every detector carries: which risks and techniques Hawk AI detects, and which it does not yet."],
            ["EU AI Act", "Optional: a deployer's view of Regulation (EU) 2024/1689."],
          ],
        },
        {
          kind: "table",
          head: ["Status", "Meaning"],
          rows: [
            ["Met", "Every Hawk AI control behind it is in force now."],
            ["Partly met", "Some are; each control says what is left."],
            ["Gap", "None is in force yet. **Next step** links to the setting that closes it; some gaps are features Hawk AI does not have yet, and say so."],
            ["Your process", "No Hawk AI control covers it: a policy, training, a contract. Owners and admins **Record** it as in place, with where its evidence is."],
            ["Recorded in place, Not applicable", "What an owner or admin recorded. A record lasts a year, then is due for review; every change is in the audit log."],
          ],
        },
        {
          kind: "p",
          text: "Filter by who does it (**Hawk AI**, **You, with Hawk AI**, **Your organisation**) and by status to see the gaps first.",
        },
        {
          kind: "note",
          tone: "warn",
          text: "Packs support compliance work: they show where Hawk AI's controls stand and gather the evidence. They do not by themselves make your organisation compliant or certified; your auditor or regulator decides that.",
        },
      ],
    },
    {
      id: "pack-evidence",
      title: "Signed evidence for a pack",
      who: "People who may export the audit log",
      blocks: [
        {
          kind: "p",
          text: "**Download signed evidence** on a pack gives one zip for a time window (the last 30 days by default, at most a year): each requirement's status, the controls behind it, the settings in force, the audit entries of the window with their sequence numbers and chain codes, licence acceptances, AI approvals, the AI system inventory and your records. `manifest.json` lists every file with its SHA-256 and is signed with this installation's evidence key. Passwords, secrets, keys and prompt text are never in it. Each download is in the audit log.",
        },
        {
          kind: "steps",
          items: [
            "Save the public keys from `/.well-known/hawk-evidence-keys.json` (or Settings → Audit log → Evidence signing).",
            "Unzip the bundle into a folder.",
            "Run `python3 tools/verify_evidence.py manifest.json --keys hawk-evidence-keys.json` there: it checks the signature and that no file changed.",
          ],
        },
      ],
    },
    {
      id: "what-it-covers",
      title: "What the Compliance page shows",
      who: "Owners, admins and auditors",
      blocks: [
        {
          kind: "p",
          text: "The second tab of [Settings → Compliance](/settings/compliance) lists each control of the Dubai Electronic Security Center's Information Security Regulation (DESC ISR), the UAE Information Assurance Standard and India's CERT-In directions that the software takes part in, with its status worked out from the settings in force and a link to where it is set or shown.",
        },
        {
          kind: "table",
          head: ["Status", "Meaning"],
          rows: [
            ["Met", "In force now."],
            ["Partly met", "Hawk AI does part of it; the page says what is left."],
            ["Needs a setting", "An owner or admin sets it here (the row links to the page)."],
            ["Customer's server", "It depends on the machine you run: the host's clock, disk encryption. Confirm it, and it shows as met."],
          ],
        },
        {
          kind: "note",
          tone: "info",
          text: "These standards are about the organisation as much as the software: an information security policy, risk assessment, HR security and awareness, supplier management, an incident response plan and team, business continuity tested yearly, internal audit and physical security. Hawk AI gives evidence for them; it cannot be them.",
        },
      ],
    },
    {
      id: "sign-in-baseline",
      title: "The recommended sign-in baseline",
      who: "Server administrators",
      blocks: [
        {
          kind: "p",
          text: "**Apply the recommended baseline** on [Settings → Compliance](/settings/compliance) sets, on [Settings → Sign-in](/settings/signin):",
        },
        {
          kind: "list",
          items: [
            "Passwords of at least 12 characters, mixing at least 3 of lower case, upper case, digits and symbols.",
            "None of the last 5 passwords may come back (their hashes are kept, never the passwords).",
            "A password lasts 90 days: at the next sign-in after that, the person chooses a new one before anything else.",
            "A sign-in ends after 15 minutes without activity (instead of `SESSION_IDLE_MINUTES`).",
          ],
        },
        {
          kind: "p",
          text: "Then, on [Settings → Sign-in](/settings/signin), write the **notice on the sign-in page** your entity requires (authorised use only, activity monitored) and require **two-step sign-in**, or use single sign-on with passwords for Admins only. Your entity's own policy decides in the end: every value can be changed.",
        },
      ],
    },
    {
      id: "clock",
      title: "The clock (NTP)",
      who: "Whoever runs the server",
      blocks: [
        {
          kind: "p",
          text: "Log times are only evidence if the clock is right. Hawk AI reads from the host's kernel whether its clock is synchronised by NTP (shown in `/api/health` as `clock` and on the Compliance page). Run chrony or systemd-timesyncd on the host; in India CERT-In asks for NIC's or NPL's servers (or servers traceable to them).",
        },
        {
          kind: "table",
          head: ["Setting", "Default", "What it does"],
          rows: [
            ["`TIME_SYNC_NTP_SERVER`", "(empty)", "An NTP server to measure this clock against (UDP 123 must be open to it), e.g. samay1.nic.in. More than one second off is reported."],
            ["`TZ`", "`UTC`", "The time zone scheduled work uses (Asia/Dubai, Asia/Kolkata). Logs and the audit log are always in UTC."],
          ],
        },
      ],
    },
    {
      id: "retention",
      title: "How long records are kept",
      who: "Server administrators",
      blocks: [
        {
          kind: "list",
          items: [
            "The audit log is never deleted: entries cannot be changed or removed.",
            "User activity: a year by default; connector API activity: 180 days. Both can be set on [Settings → Compliance](/settings/compliance), never under 180 days (CERT-In's rolling 180 days; India's DPDP Rules ask a year for processing logs).",
            "The services' own log lines (`LOG_FORMAT`) are kept by Docker by size (5 files of 20 MB a service). To keep them longer, forward them to your SIEM or log server, for example with Docker's syslog or journald logging driver.",
          ],
        },
      ],
    },
    {
      id: "residency-and-encryption",
      title: "Data location and encryption at rest",
      who: "Owners and admins",
      blocks: [
        {
          kind: "p",
          text: "Everything Hawk AI keeps stays on this server and where its backups go; nothing is sent to the vendor. State where the server is (city and country) on [Settings → Compliance](/settings/compliance), or with `DEPLOYMENT_DATA_LOCATION`; About and incident reports show it. Under DESC ISR v3 a Dubai government entity's critical information stays in the UAE.",
        },
        {
          kind: "list",
          items: [
            "Backups are encrypted with this server's backup key or `BACKUP_PASSPHRASE` ([Settings → Backups & health](/settings/backups)).",
            "Two-step secrets, the email server's password and connector credentials are encrypted in the database; passwords are bcrypt hashes.",
            "The disk itself is yours to encrypt (LUKS, BitLocker, the hypervisor's or the storage's). Set `DISK_ENCRYPTION_CONFIRMED=true` once it is, and the page shows it as confirmed.",
          ],
        },
      ],
    },
    {
      id: "siem-and-incidents",
      title: "SIEM export and the incident report",
      who: "People who may export the audit log",
      blocks: [
        {
          kind: "list",
          items: [
            "[Settings → Audit log](/settings/audit) → **Export CEF** gives one Common Event Format line per entry for ArcSight, QRadar, Sentinel or Splunk, for any time window; **Export JSON Lines** carries each entry's chain code.",
            "**Download the incident report** on [Settings → Compliance](/settings/compliance) gathers a time window's security events (24 hours by default, at most 31 days): wrong passwords and locks, changes to people, roles and settings, backups, updates and gateway decisions, with each entry's sequence number and chain code, the clock and the installation's identity, signed like every export.",
            "India: report a cyber incident to CERT-In within 6 hours of noticing it, and name a point of contact (the **incident contact** on the Compliance page). Dubai: follow your entity's incident procedure under the ISR, which reports to DESC.",
          ],
        },
      ],
    },
  ],
};
