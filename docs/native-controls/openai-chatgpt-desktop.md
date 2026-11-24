# OpenAI ChatGPT Desktop composite control


Status date: 2026-08-12  
Adapter: `chatgpt_desktop_composite`  
Schema: `chatgpt-desktop-composite/1.0`

## Scope

Hawk models ChatGPT Desktop as one discovered AI asset with action-specific control plans across Chat, local Work, cloud Work, Codex local, Codex remote, the built-in browser, apps, and custom MCP. It does not model the product as one coarse native hook.

OpenAI currently documents that the desktop app combines Chat, Work, and Codex, that local Work may use local files and desktop applications with permission, and that cloud Work is a separate execution context. OpenAI also documents the built-in browser as its own browser state rather than the user's Chrome profile. These provider facts support the composite boundary; they do not prove Hawk enforcement.

Official references:

- [ChatGPT Work and Codex](https://help.openai.com/en/articles/20001275-chatgpt-work-and-codex)
- [Using the built-in browser in the ChatGPT desktop app](https://help.openai.com/en/articles/20001277-using-the-built-in-browser-in-the-chatgpt-desktop-app)
- [Moving to the new ChatGPT desktop app](https://help.openai.com/en/articles/20001276)
- [Apps in ChatGPT](https://help.openai.com/en/articles/11487775-apps-in-chatgpt)
- [Admin controls, security, and compliance in apps](https://help.openai.com/en/articles/11509118-admin-controls-security-and-compliance-in-connectors-enterprise-edu-and-team)
- [OpenAI Compliance Platform](https://help.openai.com/en/articles/9261474-openai-compliance-platform-for-enterprise-customers)
- [Codex lifecycle hooks](https://learn.chatgpt.com/docs/hooks)

## Non-negotiable truth boundaries

- Hawk does not claim an app-wide `CHATGPT_DESKTOP_NATIVE_HOOK`. OpenAI's
  lifecycle hooks are a Codex extensibility framework used by ChatGPT Work and
  Codex; they do not establish one native hook across ordinary ChatGPT chat,
  cloud Work, apps, or the built-in browser.
- A running desktop process does not establish active mode, account type, or local execution.
- The built-in browser does not inherit Hawk's Chrome or Edge extension coverage.
- Endpoint presence does not authorize cloud-only Work or remote Codex execution.
- Compliance logs and APIs are evidence and discovery sources, never pre-action control.
- Provider denial is monotonic: a Hawk allow cannot weaken a provider deny.
- DOM click and form-field semantics are unavailable until a supported official interface is verified.
- Hawk never reads ChatGPT cookies, passwords, session tokens, prompts, or protected application storage for discovery.

## Supported discovery evidence

The endpoint collector reads only:

- macOS process metadata: PID, parent PID, executable path, user, and process start time;
- public `Info.plist` values: bundle ID, version, build, and executable name;
- macOS code-signing and execution-assessment output;
- endpoint and Hawk evidence identifiers.

A process named `ChatGPT` outside the observed signed bundle is reported as `name_only_unverified`. A process inside the bundle is not signature-verified unless strict verification succeeds. Mode, runtime, and account remain Unknown without a supported context source.

## Modes, runtime, and account

Modes are independent:

- `CHAT`
- `WORK_LOCAL`
- `WORK_CLOUD`
- `CODEX_LOCAL`
- `CODEX_REMOTE`
- `BUILT_IN_BROWSER`
- `APP_ACTION`
- `MCP_ACTION`
- `UNKNOWN_DESKTOP_MODE`

Runtime is independently classified as `LOCAL_ENDPOINT`, `OPENAI_CLOUD`, `MIXED`, or `UNKNOWN`.

Account context is `ENTERPRISE`, `BUSINESS`, `EDU`, `PERSONAL`, or `UNKNOWN`. Only OpenAI admin or Compliance context, SSO/workspace binding, existing Hawk identity binding, or an approved application context is authoritative. Process names, email-domain strings, and network destinations are rejected as account evidence. Supported authoritative changes generate account-switch context; Hawk does not infer a switch from weak hints.

## Action-specific control plans

| Action | Mandatory local consequence floors | Semantic/provider context | Evidence |
|---|---|---|---|
| Chat prompt | Network | Workspace/account policy | Endpoint |
| Chat file upload | File read + Network | Legitimate local semantic proxy when available | Endpoint |
| Work local file read | File read | Hawk purpose and data policy | Endpoint |
| Work local file write | File write | Hawk purpose and data policy | Endpoint |
| Work desktop app | File read/write + Process + Network | Exact UI semantics only when supported | Endpoint |
| Cloud Work | None | OpenAI workspace/runtime/app control | Compliance/runtime |
| Built-in browser navigation | Network | Local semantic proxy and provider website context when supported | Endpoint + Compliance |
| Built-in browser upload | File read + Network | Local semantic proxy when legitimate | Endpoint |
| Built-in browser download | Network + File write | Local semantic proxy when legitimate | Endpoint |
| App action | Network for local initiation | Provider action control as monotonic floor; Hawk path where available | Provider + Endpoint + Compliance |
| Custom MCP write | Network for local initiation | Hawk MCP Gateway + provider action control | MCP + Endpoint + Compliance |
| Codex local shell | File read/write + Process + Network | Existing Codex adapter | Codex + Endpoint |
| Codex remote | None | Existing remote runtime control | Codex/runtime |

Unknown runtime never acquires a local-authority claim. Known file, process, or network consequences may still carry their applicable floor even when exact UI semantics are unavailable.

## Built-in browser

`CHATGPT_BUILT_IN_BROWSER` is a contextual sub-surface, not a deployment family. Its endpoint-observable context may include the parent ChatGPT process, attributable network flow, destination, correlated upload/download file consequences, workspace context, and evidence references.

The Endpoint Network Floor can control a destination without DOM knowledge. Sensitive upload requires file-read authorization before the process receives content, then network-destination authorization. Download requires the source connection and the resulting file write to be controlled and correlated as one action where evidence supports that correlation.

Hawk does not extract passwords, cookies, autofill data, or session tokens. It does not weaken application TLS. If policy requires content semantics and a legitimate semantic path is unavailable, policy must block or require an exception rather than bypass TLS protections.

Promotion of built-in-browser endpoint control requires real safe tests proving attributed network allow/block, file-read denial before upload, download file-write control, ordinary transport-change resistance, health-failure detection, and immediate Control Coverage downgrade. That gate has not passed.

## Work local and cloud separation

Local Work file and application consequences remain subject to the Endpoint Floor. Exact UI mutation is not claimed when only file, child-process, network, or local-service consequences are visible.

Cloud Work never inherits endpoint execution control. It requires authoritative workspace/runtime/app controls and post-action provider evidence. Desktop initiation may contribute identity or session context but does not prove cloud-side authorization.

## Apps and custom MCP

Hawk consumes authoritative per-app access, action, approval, and connection context. Capabilities remain per app. OpenAI's current documentation describes workspace app access and action controls; Hawk treats stricter provider controls as a monotonic safety floor.

Customer-controlled MCP may use:

`ChatGPT → Hawk MCP Gateway → enterprise service`

That path can bind tool, arguments, target, destination, identity, purpose, decision receipt, and execution receipt. OpenAI-managed apps are not forced through a fictitious MCP path.

## Compliance reconciliation

Enterprise/Edu Compliance data is evidence-only. Hawk can reconcile endpoint and provider events as:

- `CONFIRMED`
- `CORRELATED`
- `MISSING_PROVIDER_EVIDENCE`
- `MISSING_ENDPOINT_EVIDENCE`
- `UNKNOWN`

A missing event is a coverage gap requiring investigation; it is not automatically labeled malicious bypass.

## Codex composition

The composite adapter reuses `CodexNativeControlAdapter`; it does not implement a second Codex adapter. Local Codex combines existing lifecycle-hook evidence with mandatory Endpoint File, Process, and Network floors. Remote Codex is a separate runtime and never inherits local endpoint execution authority.

The repository currently classifies the Codex adapter as Experimental. A composite Codex-local capability therefore cannot become Verified, and an unverified mandatory endpoint floor degrades it further.

## Endpoint health and selector behavior

The asset projection consumes the latest authenticated endpoint heartbeat for the tenant. A heartbeat older than five minutes is stale. A local control is accepted as runtime-verified only when all of the following are present:

- inline or inline-bound status;
- Verified status;
- Healthy health;
- concrete evidence references;
- fresh signed local policy;
- measured latency within the action floor's budget when the Trusted Control Point Selector evaluates it;
- a repository capability profile that is itself Verified.

Aggregate `protected` or `minimum_floor_satisfied` input fields are ignored and recalculated. Current Endpoint Floor profiles are Unverified, so source presence or a self-asserted heartbeat cannot produce an authoritative selector result.

## Capability matrix

The asset view independently reports 20 dimensions: Chat network/upload; Work local read/write, desktop app, and cloud; built-in-browser network, destination, HTTP semantics, DOM, upload, and download; app access/action/approval; custom MCP; Compliance visibility; Codex local/remote; and account identity.

Each row carries level, verification, evidence references, control role, and blind spots. Control Coverage is an unweighted count of Verified rows out of 20; Partial, Experimental, Unverified, Unavailable, and Unknown never count as Verified. There is no ChatGPT-wide green check.

## Current exact installed-app observation

Observed on 2026-08-12 at `/Applications/ChatGPT.app`:

| Field | Observed value |
|---|---|
| Bundle ID | `com.openai.codex` |
| Version | `26.715.31925` |
| Build | `5551` |
| Embedded Team ID | `2DC432GLL2` |
| Embedded CDHash | `fbb99a1f03f8a104ef0d79dcd772a3aa224b6e84` |
| Hardened-runtime flag | Present |
| Stapled ticket | Present in signature metadata |
| Strict signature verification | Failed: installed code or signature reported modified |
| macOS execution assessment | Failed with a Code Signing subsystem error |
| Hawk native-hook claim | `false` |

The Team ID, CDHash, and stapled-ticket metadata do not override the strict verification failure. Hawk correctly classifies this installation as signature-unverified. Reinstalling an official clean build and rerunning acceptance is required before reliable app-identity promotion.

## APIs and UI

- `GET /native-controls/chatgpt-desktop/assets` returns tenant-scoped server-projected assets from at most 500 recent evidence records.
- `POST /native-controls/chatgpt-desktop/control-plan` resolves a read-only action plan from the endpoint ID and action class. The server derives mode/runtime/account context and never accepts a client aggregate protection claim.
- AI Asset Intelligence shows installation/process identity, account, modes, built-in browser, Endpoint Floor, all 20 capabilities, an evidence-only reconciliation view, blind spots, and a read-only “Why this action is controlled” explorer.

## Remaining promotion gates

- Install a clean strictly signature-valid ChatGPT desktop build and rerun exact-version acceptance.
- Complete verified native macOS Endpoint File, Process, and Network implementations with measured latency and managed activation.
- Run real safe Chat, local Work, cloud Work, built-in-browser allow/block/upload/download, app, custom MCP, Compliance, and Codex composition acceptance.
- Enroll authoritative tenant workspace/admin and Compliance credentials.
- Prove account switching using supported workspace evidence.
- Prove QUIC/alternate-route attribution or surface it as uncovered.
- Promote only the individually proven capability rows.
