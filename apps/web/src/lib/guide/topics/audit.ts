import type { GuideTopic } from "../types";

/**
 * app/services/audit_chain.py, app/cli/audit_verify.py, app/services/evidence_signing.py,
 * app/api/routers/evidence_signing.py, tools/verify_evidence.py, Settings → Audit log.
 */
export const audit: GuideTopic = {
  slug: "audit-and-evidence",
  title: "Audit log and evidence",
  summary: "What the audit log records, checking it has not been changed, exports, and the signature an auditor checks offline with the public key alone.",
  sections: [
    {
      id: "audit-log",
      title: "The audit log",
      who: "People who may see the audit log",
      blocks: [
        {
          kind: "p",
          text: "[Settings → Audit log](/settings/audit) shows every action, by everyone: sign-ins, changes to people, connectors, policies and settings, exports and downloads, backups and support requests, and anything refused, with the reason. Newest first, with filters. [Connector API activity](/settings/connector-activity) lists Hawk AI's own calls to the services its connectors use.",
        },
      ],
    },
    {
      id: "integrity-check",
      title: "Check the log is intact",
      who: "People who may see the audit log",
      blocks: [
        {
          kind: "p",
          text: "Each entry is chained to the one before, so an entry that was changed, removed or put out of order is found. **Check the log is intact** on the page names every broken entry. On the server, the same check for every tenant's log and the system's:",
        },
        {
          kind: "code",
          lines: ["docker compose -f deploy/compose.yaml exec api python -m app.cli.audit_verify"],
          caption: "Exits 0 when every chain is intact, 1 when an entry was edited, removed or reordered, 2 when the check could not run.",
        },
      ],
    },
    {
      id: "exports",
      title: "Exports",
      who: "People who may export the audit log",
      blocks: [
        {
          kind: "list",
          items: [
            "**Export CSV** downloads `audit.csv`, with the filters in use.",
            "**Export JSON Lines** downloads `audit.jsonl`: every entry with its chain code, for a SIEM.",
            "**Export CEF** downloads `audit.cef`: one ArcSight Common Event Format line per entry (who, from where, what, the outcome, the sequence number and chain code), which ArcSight, QRadar, Microsoft Sentinel and Splunk read as they are.",
            "Each export comes with its signature beside it (`audit.csv.sig.json`, `audit.jsonl.sig.json`, `audit.cef.sig.json`). The activity and connector exports, and the auditor's export under Reports → Automated Auditor (a signed list of all its files), are signed the same way.",
          ],
        },
      ],
    },
    {
      id: "evidence-signing",
      title: "Evidence signing",
      blocks: [
        {
          kind: "p",
          text: "Evidence that leaves Hawk AI is signed with a private key only Hawk AI holds. Anyone can check it offline with the public key alone. The Evidence signing panel on [Settings → Audit log](/settings/audit) shows the key's fingerprint, its algorithm, since when it is in use, and the keys retired before.",
        },
        {
          kind: "table",
          head: ["`EVIDENCE_SIGNING_BACKEND`", "Where the key is"],
          rows: [
            ["`local` (default)", "An Ed25519 key made once for this installation, in the data folder. It is in every backup, so a restored server signs with the same key."],
            ["`aws_kms`", "An AWS KMS key (ECC_NIST_P256, SIGN_VERIFY): `EVIDENCE_SIGNING_AWS_KMS_KEY_ID`, `EVIDENCE_SIGNING_AWS_REGION` and static credentials (`EVIDENCE_SIGNING_AWS_ACCESS_KEY_ID`, `EVIDENCE_SIGNING_AWS_SECRET_ACCESS_KEY`). Instance roles are not read."],
            ["`azure_kv`", "An Azure Key Vault EC key on P-256: `EVIDENCE_SIGNING_AZURE_KEY_ID` and an app registration (`EVIDENCE_SIGNING_AZURE_TENANT_ID`, `EVIDENCE_SIGNING_AZURE_CLIENT_ID`, `EVIDENCE_SIGNING_AZURE_CLIENT_SECRET`). Managed identities are not read."],
            ["`gcp_kms`", "A Cloud KMS key version (EC_SIGN_P256_SHA256): `EVIDENCE_SIGNING_GCP_KEY_VERSION` and a service account key in `EVIDENCE_SIGNING_GCP_CREDENTIALS_JSON`. Workload identity is not read."],
          ],
        },
        {
          kind: "p",
          text: "**Rotate the signing key** (owners and admins) makes a new local key, or reads the cloud key again. Old public keys stay published, so evidence signed before a rotation stays checkable.",
        },
      ],
    },
    {
      id: "verify-offline",
      title: "Check evidence offline",
      blocks: [
        {
          kind: "p",
          text: "The public keys, current and retired, are published at `/.well-known/hawk-evidence-keys.json` on Hawk AI's address (for example `https://hawk.company.com/.well-known/hawk-evidence-keys.json`). Save that file and give it, with the evidence, to `tools/verify_evidence.py` from the Hawk AI folder. It needs Python 3.9 or later and the `cryptography` package; no server, account or secret.",
        },
        {
          kind: "code",
          lines: [
            "python3 tools/verify_evidence.py audit.csv --signature audit.csv.sig.json --keys hawk-evidence-keys.json",
            "python3 tools/verify_evidence.py audit_export_manifest_....json --keys hawk-evidence-keys.json --dir ./export",
            "python3 tools/verify_evidence.py audit_evidence_pack_....json --keys hawk-evidence-keys.json",
          ],
          caption: "An export with its signature beside it; the auditor's export and every file it lists; a JSON document with its signature inside.",
        },
        {
          kind: "p",
          text: "It exits 0 when every check passes, 1 when one fails and 2 when the command is wrong; `--json` prints the result as JSON.",
        },
      ],
    },
  ],
};
